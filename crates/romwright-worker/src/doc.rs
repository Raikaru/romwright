//! Packed-document decoder (WORKER-004).
//!
//! The decompiler's `<doc>` response is decoded with the same packed grammar
//! as `ghidra/program/model/pcode/PackedDecode.java` in the pinned Ghidra
//! source tree. This module never reconstructs metadata by parsing rendered
//! C text.
//!
//! `PackedDecode.java:55-77` defines the header and value codes:
//! `0x40` element start, `0x80` element end, `0xc0` attribute; ids use a
//! five-bit header and an optional seven-bit continuation. Attribute values
//! use type codes 1 (boolean), 2/3 (signed integer), 4 (unsigned integer),
//! 5 (address-space), 6 (special space), and 7 (string). Integer payloads
//! are big-endian seven-bit groups. String lengths are themselves encoded as
//! a packed integer before the string bytes (`PackedDecode.java:180-195`).

use crate::wire::elem::{ADDR, DOC, FUNCTION};
use romwright_model::function_ir::{OperationId, ValueId};
use romwright_model::{Address, AddressSpace, DecompToken, FuncProto, JumpTable, TokenKind};

/// The decoded payload, before its caller assigns the request and store revision.
pub struct DecodedDocument {
    pub tokens: Vec<DecompToken>,
    pub prototype: Option<FuncProto>,
    pub call_prototypes: std::collections::BTreeMap<OperationId, FuncProto>,
    pub call_targets: std::collections::BTreeMap<OperationId, Address>,
    pub jump_tables: Option<Vec<JumpTable>>,
    pub storage: Vec<romwright_model::StorageSymbol>,
    pub function_ir: Option<romwright_model::function_ir::FunctionIr>,
    pub semantic_error: Option<String>,
    pub cut_projection: Vec<(
        romwright_model::function_ir::ControlFlowCut,
        romwright_model::function_ir::ControlFlowCut,
    )>,
}

// funcdata.cc and jumptable.cc packed element tables.
const JUMPTABLELIST: u32 = 118;
const JUMPTABLE: u32 = 213;
const DEST: u32 = 212;

/// Token element ids, verified against `ElementId.java` and `ClangToken.java`.
const ELEM_VALUE: u32 = 9;
const ELEM_BREAK: u32 = 17;
const ELEM_FUNCNAME: u32 = 19;
const ELEM_LABEL: u32 = 21;
const ELEM_SYNTAX: u32 = 24;
const ELEM_VARIABLE: u32 = 26;
const ELEM_OP: u32 = 27;
const ELEM_FIELD: u32 = 49;
const ELEM_TYPE: u32 = 60;
const ELEM_COMMENT: u32 = 86;
const ELEM_BITFIELD: u32 = 289;

/// Attribute ids verified against `AttributeId.java` and the Clang token
/// decoders. `ATTRIB_OFF` is used by labels/comments; `ATTRIB_OFFSET` is used
/// by fields and is deliberately not treated as an address.
const ATTRIB_CONTENT: u32 = 1;
const ATTRIB_ID: u32 = 9;
const ATTRIB_NAME: u32 = 14;
const ATTRIB_OFFSET: u32 = 16;
const ATTRIB_SPACE: u32 = 20;
const ATTRIB_COLOR: u32 = 37;
const ATTRIB_OFF: u32 = 39;
const ATTRIB_OPREF: u32 = 41;
const ATTRIB_VARREF: u32 = 42;
const ATTRIB_INDENT: u32 = 38;
const ATTRIB_SYMREF: u32 = 68;

const TAG_ELEMENT_START: u8 = 0x40;
const TAG_ELEMENT_END: u8 = 0x80;
const TAG_ATTRIBUTE: u8 = 0xc0;

const TYPECODE_BOOLEAN: u8 = 1;
const TYPECODE_SIGNED_POSITIVE: u8 = 2;
const TYPECODE_SIGNED_NEGATIVE: u8 = 3;
const TYPECODE_UNSIGNED: u8 = 4;
const TYPECODE_SPACE: u8 = 5;
const TYPECODE_SPECIAL: u8 = 6;
const TYPECODE_STRING: u8 = 7;

fn kind_of(eid: u32) -> TokenKind {
    match eid {
        ELEM_VALUE => TokenKind::Value,
        ELEM_BREAK => TokenKind::Break,
        ELEM_FUNCNAME => TokenKind::FuncName,
        ELEM_LABEL => TokenKind::Label,
        ELEM_SYNTAX => TokenKind::Syntax,
        ELEM_VARIABLE => TokenKind::Variable,
        ELEM_OP => TokenKind::Op,
        ELEM_FIELD => TokenKind::Field,
        ELEM_TYPE => TokenKind::Type,
        ELEM_COMMENT => TokenKind::Comment,
        ELEM_BITFIELD => TokenKind::Bitfield,
        _ => TokenKind::Other,
    }
}

fn is_token(eid: u32) -> bool {
    matches!(
        eid,
        ELEM_VALUE
            | ELEM_BREAK
            | ELEM_FUNCNAME
            | ELEM_LABEL
            | ELEM_SYNTAX
            | ELEM_VARIABLE
            | ELEM_OP
            | ELEM_FIELD
            | ELEM_TYPE
            | ELEM_COMMENT
            | ELEM_BITFIELD
    )
}

#[derive(Clone, Debug)]
pub(crate) enum Value {
    Boolean(bool),
    Signed(i64),
    Unsigned(u64),
    Space(u64),
    Special(u8),
    String(String),
}

impl Value {
    pub(crate) fn unsigned(&self) -> Option<u64> {
        match self {
            Self::Unsigned(v) | Self::Space(v) => Some(*v),
            Self::Signed(v) if *v >= 0 => Some(*v as u64),
            _ => None,
        }
    }

    pub(crate) fn signed(&self) -> Option<i64> {
        match self {
            Self::Signed(v) => Some(*v),
            Self::Unsigned(v) => i64::try_from(*v).ok(),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Default)]
struct Ctx {
    id: u32,
    color: u8,
    name: Option<String>,
    symbol_id: Option<u64>,
    space: Option<u64>,
    address_offset: Option<u64>,
    varnode: Option<ValueId>,
    operation: Option<OperationId>,
    datatype_id: Option<u64>,
    indent: Option<i64>,
    content_seen: bool,
}

impl Ctx {
    fn address(&self, ram_space_index: Option<u64>) -> Option<Address> {
        let space = self.space?;
        let offset = self.address_offset?;
        Some(Address {
            space: if ram_space_index == Some(space) {
                AddressSpace::Ram
            } else {
                AddressSpace::Other(format!("space:{space}"))
            },
            offset,
        })
    }
}

#[derive(Default)]
struct SwitchCollector {
    function_depth: Option<usize>,
    structural: bool,
    table_depth: Option<usize>,
    branch: Option<Address>,
    targets: Vec<Address>,
    tables: Vec<JumpTable>,
    result: Option<Vec<JumpTable>>,
    failed: bool,
}

impl SwitchCollector {
    fn start(&mut self, id: u32, parent: Option<u32>, depth: usize) {
        if id == FUNCTION && parent == Some(DOC) {
            self.function_depth = Some(depth);
            self.structural = false;
        }
        if id == JUMPTABLE
            && parent == Some(JUMPTABLELIST)
            && self.function_depth == depth.checked_sub(2)
        {
            self.table_depth = Some(depth);
        }
    }

    fn end(&mut self, ctx: &Ctx, depth: usize, ram_space_index: Option<u64>) {
        if ctx.id == ADDR && self.function_depth == depth.checked_sub(1) {
            self.structural = ctx.space.is_some() && ctx.address_offset.is_some();
            self.failed |= !self.structural;
        }
        if self.table_depth == depth.checked_sub(1) && matches!(ctx.id, ADDR | DEST) {
            if let Some(address) = ctx.address(ram_space_index) {
                if ctx.id == ADDR {
                    self.failed |= self.branch.replace(address).is_some();
                } else {
                    self.targets.push(address);
                }
            } else {
                self.failed = true;
            }
        }
        if ctx.id == JUMPTABLE && self.table_depth == Some(depth) {
            match self.branch.take() {
                Some(branch) if !self.targets.is_empty() => {
                    self.tables.push(JumpTable {
                        branch,
                        targets: std::mem::take(&mut self.targets),
                    });
                }
                _ => self.failed = true,
            }
            self.table_depth = None;
        }
        if ctx.id == FUNCTION && self.function_depth == Some(depth) {
            if self.structural {
                self.failed |= self
                    .result
                    .replace(std::mem::take(&mut self.tables))
                    .is_some();
            } else if !self.tables.is_empty() {
                self.failed = true;
            }
            self.function_depth = None;
        }
    }

    fn finish(self) -> Option<Vec<JumpTable>> {
        if self.failed || self.function_depth.is_some() || self.table_depth.is_some() {
            None
        } else {
            self.result
        }
    }
}

fn read_id_after_header(packed: &[u8], p: &mut usize, h: u8) -> Option<u32> {
    let mut id = (h & 0x1f) as u32;
    if h & 0x20 != 0 {
        id = (id << 7) | (*packed.get(*p)? & 0x7f) as u32;
        *p += 1;
    }
    Some(id)
}

/// Reads the packed integer used by `PackedDecode.readInteger`.
fn read_groups(packed: &[u8], p: &mut usize, groups: usize) -> Option<u64> {
    let mut value = 0u64;
    for _ in 0..groups {
        value = value
            .checked_mul(128)?
            .checked_add((*packed.get(*p)? & 0x7f) as u64)?;
        *p += 1;
    }
    Some(value)
}

/// Reads one complete attribute value, including the string length field.
fn read_value(packed: &[u8], p: &mut usize) -> Option<Value> {
    let type_byte = *packed.get(*p)?;
    *p += 1;
    let type_code = type_byte >> 4;
    let length = (type_byte & 0x0f) as usize;
    match type_code {
        TYPECODE_BOOLEAN => Some(Value::Boolean(length != 0)),
        TYPECODE_SIGNED_POSITIVE => Some(Value::Signed(
            i64::try_from(read_groups(packed, p, length)?).ok()?,
        )),
        TYPECODE_SIGNED_NEGATIVE => {
            let magnitude = i64::try_from(read_groups(packed, p, length)?).ok()?;
            Some(Value::Signed(magnitude.checked_neg()?))
        }
        TYPECODE_UNSIGNED => Some(Value::Unsigned(read_groups(packed, p, length)?)),
        TYPECODE_SPACE => Some(Value::Space(read_groups(packed, p, length)?)),
        TYPECODE_SPECIAL => Some(Value::Special(length as u8)),
        TYPECODE_STRING => {
            let byte_len = usize::try_from(read_groups(packed, p, length)?).ok()?;
            let bytes = packed.get(*p..p.checked_add(byte_len)?)?;
            *p += byte_len;
            Some(Value::String(String::from_utf8_lossy(bytes).into_owned()))
        }
        // PackedDecode skips unknown value types by their group count. Keep
        // the parser aligned and reject the value rather than guessing its
        // meaning.
        _ => {
            let _ = read_groups(packed, p, length)?;
            None
        }
    }
}

fn token_from_context(ctx: &Ctx, text: String, ram_space_index: Option<u64>) -> DecompToken {
    let address = ctx.address(ram_space_index);
    DecompToken {
        text,
        kind: kind_of(ctx.id),
        color: ctx.color,
        symbol: ctx.name.clone(),
        symbol_id: ctx.symbol_id,
        address,
        varnode: ctx.varnode,
        operation: ctx.operation,
        datatype_id: ctx.datatype_id,
        indent: ctx.indent,
    }
}

/// Decodes a packed `<doc>` payload without assuming a RAM-space index.
///
/// Addressed tokens retain the numeric Ghidra space identity as
/// `AddressSpace::Other("space:N")`. Call [`decode_tokens_with_ram_space`]
/// when the worker has loaded the language's actual RAM index.
pub fn decode_tokens(packed: &[u8]) -> Vec<DecompToken> {
    decode_tokens_with_ram_space(packed, None)
}

/// Decodes a packed `<doc>` payload and maps the configured RAM space to the
/// model's typed `AddressSpace::Ram`; all other numeric spaces remain named
/// `Other` values instead of being silently flattened into RAM.
pub fn decode_tokens_with_ram_space(
    packed: &[u8],
    ram_space_index: Option<u64>,
) -> Vec<DecompToken> {
    decode_packed(packed, ram_space_index, false).tokens
}

/// Decode tokens and recovered native metadata in one pass. Missing or
/// incomplete structural data stays unknown, never a guessed empty result.
pub fn decode_document_with_ram_space(
    packed: &[u8],
    ram_space_index: Option<u64>,
) -> DecodedDocument {
    decode_packed(packed, ram_space_index, true)
}

fn decode_packed(
    packed: &[u8],
    ram_space_index: Option<u64>,
    collect_metadata: bool,
) -> DecodedDocument {
    let mut tokens = Vec::new();
    let mut stack: Vec<Ctx> = Vec::new();
    let mut prototype = collect_metadata.then(crate::prototype::Collector::default);
    let mut switches = collect_metadata.then(SwitchCollector::default);
    let mut semantic = collect_metadata.then(crate::semantic::Collector::default);
    let mut valid = true;
    let mut p = 0usize;
    while p < packed.len() {
        let header = packed[p];
        p += 1;
        match header & 0xc0 {
            TAG_ELEMENT_START => {
                let Some(id) = read_id_after_header(packed, &mut p, header) else {
                    valid = false;
                    break;
                };
                if let Some(semantic) = semantic.as_mut() {
                    semantic.start(id, stack.last().map(|ctx| ctx.id), stack.len() + 1);
                }
                if let Some(prototype) = prototype.as_mut() {
                    prototype.start(id, stack.last().map(|ctx| ctx.id), stack.len() + 1);
                }
                if let Some(switches) = switches.as_mut() {
                    switches.start(id, stack.last().map(|ctx| ctx.id), stack.len() + 1);
                }
                stack.push(Ctx {
                    id,
                    symbol_id: stack.last().and_then(|parent| parent.symbol_id),
                    ..Ctx::default()
                });
            }
            TAG_ELEMENT_END => {
                let Some(id) = read_id_after_header(packed, &mut p, header) else {
                    valid = false;
                    break;
                };
                let Some(ctx) = stack.pop() else {
                    valid = false;
                    continue;
                };
                // A malformed close must not make us associate subsequent
                // content with the wrong element. Valid Ghidra streams always
                // close the top id (`PackedDecode.closeElement`, lines 318-330).
                if ctx.id != id {
                    valid = false;
                    stack.clear();
                    continue;
                }
                if let Some(semantic) = semantic.as_mut() {
                    semantic.end(id, stack.len() + 1);
                }
                if let Some(prototype) = prototype.as_mut() {
                    prototype.end(id, stack.len() + 1);
                }
                if let Some(switches) = switches.as_mut() {
                    switches.end(&ctx, stack.len() + 1, ram_space_index);
                }
                // ClangBreak intentionally has no XMLcontent; its Java
                // decoder sets text to empty and carries only ATTRIB_INDENT.
                if ctx.id == ELEM_BREAK && !ctx.content_seen {
                    tokens.push(token_from_context(&ctx, String::new(), ram_space_index));
                }
            }
            TAG_ATTRIBUTE => {
                let Some(attrid) = read_id_after_header(packed, &mut p, header) else {
                    valid = false;
                    break;
                };
                let Some(value) = read_value(packed, &mut p) else {
                    // A malformed/unknown value cannot be safely skipped
                    // beyond the type-specific parser; stop at this point.
                    valid = false;
                    break;
                };
                let value = if let Some(semantic) = semantic.as_mut() {
                    let Some(value) = semantic.attribute(attrid, value, stack.len()) else {
                        continue;
                    };
                    value
                } else {
                    value
                };
                let value = if let Some(prototype) = prototype.as_mut() {
                    let Some(value) = prototype.attribute(attrid, value, stack.len()) else {
                        continue;
                    };
                    value
                } else {
                    value
                };
                let Some(ctx) = stack.last_mut() else {
                    valid = false;
                    continue;
                };
                if attrid == ATTRIB_CONTENT {
                    if let Value::String(text) = value {
                        ctx.content_seen = true;
                        let snapshot = ctx.clone();
                        if is_token(snapshot.id) {
                            tokens.push(token_from_context(&snapshot, text, ram_space_index));
                        }
                    }
                } else {
                    match attrid {
                        ATTRIB_COLOR => {
                            if let Some(v) = value.unsigned() {
                                // ClangToken.decode resets out-of-range colors
                                // to DEFAULT_COLOR (ClangToken.java:200-214).
                                ctx.color = u8::try_from(v).ok().filter(|v| *v < 8).unwrap_or(0);
                            }
                        }
                        ATTRIB_NAME => {
                            if let Value::String(name) = value {
                                ctx.name = Some(name);
                            }
                        }
                        ATTRIB_SYMREF => {
                            ctx.symbol_id = value.unsigned();
                        }
                        ATTRIB_SPACE => {
                            if collect_metadata
                                && matches!(ctx.id, ADDR | DEST)
                                && ctx.space.is_some()
                            {
                                valid = false;
                            }
                            ctx.space = value.unsigned();
                        }
                        ATTRIB_OFF => {
                            ctx.address_offset = value.unsigned();
                        }
                        ATTRIB_OPREF => {
                            ctx.operation = value.unsigned().map(OperationId);
                        }
                        ATTRIB_VARREF => {
                            ctx.varnode = value.unsigned().map(ValueId);
                        }
                        ATTRIB_ID => {
                            ctx.datatype_id = value.unsigned();
                        }
                        ATTRIB_INDENT => {
                            ctx.indent = value.signed();
                        }
                        // Structural addresses use OFFSET; Clang field offsets
                        // are not memory addresses and remain ignored.
                        ATTRIB_OFFSET if collect_metadata && matches!(ctx.id, ADDR | DEST) => {
                            if ctx.address_offset.is_some() {
                                valid = false;
                            }
                            ctx.address_offset = value.unsigned();
                        }
                        ATTRIB_OFFSET => {}
                        _ => {}
                    }
                }
            }
            // PackedDecode rejects these as top-level stream elements, but a
            // malformed payload should still terminate safely rather than
            // indexing past the buffer.
            _ => {
                valid = false;
                break;
            }
        }
    }
    let complete = valid && stack.is_empty();
    let recovered = if complete {
        prototype
            .map(|collector| collector.finish(ram_space_index))
            .unwrap_or_default()
    } else {
        crate::prototype::Recovered::default()
    };
    let (function_ir, cut_projection, semantic_error) = match semantic
        .map(|collector| collector.finish(complete, ram_space_index))
        .transpose()
    {
        Ok(Some((ir, projections))) => (ir, projections, None),
        Ok(None) => (None, Vec::new(), None),
        Err(error) => (None, Vec::new(), Some(error)),
    };
    DecodedDocument {
        tokens,
        prototype: recovered.prototype,
        call_prototypes: recovered.call_prototypes,
        call_targets: recovered.call_targets,
        jump_tables: if complete {
            switches.and_then(SwitchCollector::finish)
        } else {
            None
        },
        storage: recovered.storage,
        function_ir,
        semantic_error,
        cut_projection,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovers_captured_add_prototype_alongside_tokens() {
        let raw = include_bytes!("../fixtures/doc_add.bin");
        let decoded = decode_document_with_ram_space(raw, Some(3));
        let prototype = decoded
            .prototype
            .expect("captured function has a recovered prototype");
        assert_eq!(prototype.calling_convention, "__stdcall");
        assert_eq!(prototype.return_type.name.as_deref(), Some("int"));
        assert!(!prototype.variadic);
        assert_eq!(prototype.parameters.len(), 2);
        for (ordinal, parameter) in prototype.parameters.iter().enumerate() {
            assert_eq!(parameter.ordinal, ordinal as u32);
            assert_eq!(parameter.name, format!("param_{}", ordinal + 1));
            assert_eq!(parameter.data_type.name.as_deref(), Some("int"));
        }
    }

    #[test]
    fn global_token_resolves_both_its_value_and_consuming_operation() {
        use romwright_model::function_ir::{Opcode, Operand};

        // Real native response for: float scale(float x) { return x * multiplier; }
        // Its global token carries both VARREF and OPREF, including operation zero.
        let decoded =
            decode_document_with_ram_space(include_bytes!("../fixtures/doc_global.bin"), Some(3));
        assert!(
            decoded.semantic_error.is_none(),
            "{:?}",
            decoded.semantic_error
        );
        let token = decoded
            .tokens
            .iter()
            .find(|token| token.text == "multiplier")
            .unwrap();
        let ir = decoded.function_ir.unwrap();
        let value = token
            .varnode
            .expect("global must retain its SSA value identity");
        let high = ir
            .high_variables
            .iter()
            .find(|high| high.members.contains(&value))
            .unwrap();
        let symbol = high.symbol.as_ref().unwrap();
        assert!(symbol.global);
        assert_eq!(symbol.address, Some(Address::ram(0x403004)));
        let operation = ir
            .blocks
            .iter()
            .flat_map(|block| &block.operations)
            .find(|operation| Some(operation.id) == token.operation)
            .unwrap();
        assert_eq!(operation.opcode, Opcode::FLOAT_MULT);
        assert!(operation.inputs.iter().any(|operand| {
            matches!(operand, Operand::Value(value) if high.members.contains(value))
        }));
    }

    #[cfg(unix)]
    #[test]
    fn inferred_stack_declarations_preserve_signed_loop_exits() {
        use romwright_core::func_ir::{Pipeline, TransformContext};
        let mut decoded =
            decode_document_with_ram_space(include_bytes!("../fixtures/doc_cuts.bin"), Some(3));
        let ir = decoded.function_ir.as_mut().unwrap();
        let pipeline = Pipeline::from_names(&[]).unwrap();
        let context = TransformContext::default();
        let plan = pipeline.run(ir, &context).unwrap();
        pipeline.finish(ir, plan, &context).unwrap();
        let doc = romwright_model::DecompDoc {
            tokens: decoded.tokens,
            prototype: decoded.prototype,
            call_prototypes: decoded.call_prototypes,
            call_targets: decoded.call_targets,
            jump_tables: decoded.jump_tables,
            address: Address::ram(0x400446),
            revision: 0,
            storage: decoded.storage,
            function_ir: decoded.function_ir,
        };
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("romwright-ir-c-{}-{stamp}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let source = directory.join("loop.c");
        let executable = directory.join("loop");
        // An unsigned counter turns count=0 into billions of loop iterations.
        // The alarm makes that regression bounded, not a hung test suite.
        std::fs::write(&source, format!(
            "#include <unistd.h>\ntypedef unsigned int uint;\n{}\n\
             int main(void) {{ alarm(2); return cut_loop(0,0)!=10 || cut_loop(0,1)!=4 || cut_loop(3,2)!=26; }}\n",
            romwright_core::emit_m2c::render_doc_text(&doc),
        )).unwrap();
        let compiled = std::process::Command::new("cc")
            .args(["-std=c11", "-O1"])
            .arg(&source)
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap();
        let executed = compiled
            .status
            .success()
            .then(|| std::process::Command::new(&executable).status().unwrap());
        std::fs::remove_dir_all(&directory).unwrap();
        assert!(
            compiled.status.success(),
            "{}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        assert!(
            executed.unwrap().success(),
            "signed loop exit semantics changed"
        );
    }

    #[test]
    fn evidence_pass_cannot_change_an_ssa_values_width() {
        use romwright_core::func_ir::{EvidencePass, Pass, Pipeline, TransformContext};
        use romwright_model::{
            function_ir::{FunctionIr, ValueId},
            type_evidence::Class,
        };
        use std::collections::BTreeMap;
        struct WrongWidth;
        impl EvidencePass for WrongWidth {
            fn name(&self) -> &'static str {
                "wrong_width"
            }
            fn analyze(
                &self,
                ir: &FunctionIr,
                _: &TransformContext,
            ) -> Result<BTreeMap<ValueId, Class>, String> {
                let id = *ir
                    .values
                    .iter()
                    .find(|(_, value)| value.size == Some(4))
                    .unwrap()
                    .0;
                Ok(BTreeMap::from([(id, Class::Float(64))]))
            }
        }
        let ir =
            decode_document_with_ram_space(include_bytes!("../fixtures/doc_global.bin"), Some(3))
                .function_ir
                .unwrap();
        let mut pipeline = Pipeline::default();
        pipeline.add(Pass::Analyze(Box::new(WrongWidth))).unwrap();
        assert!(pipeline.run(&ir, &TransformContext::default()).is_err());
    }
}
