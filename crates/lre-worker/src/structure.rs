//! Control-flow structuring through the decompiler's own `structureGraph`.
//!
//! Ghidra's decompiler already exposes structuring as a standalone service:
//! `ghidra_process.cc`'s `StructureGraph` command (registered as
//! `structureGraph`, :503) takes an encoded `BlockGraph`, runs
//! `structureLoops`, `calcForwardDominator` and `CollapseStructure` over a
//! *copy* of it, and returns the collapsed hierarchy. No function, no p-code
//! and no decompilation are involved: the input is a control-flow graph, the
//! output is that graph's structure.
//!
//! That makes it the seam this project needs. Our own structuring can be
//! measured against stock on *identical input* -- the same basic blocks and
//! the same edges, taken from facts we already store -- so a goto count is a
//! comparison of two algorithms rather than of two pipelines. It also needs
//! no patch against the pinned tree: the command has been there all along.
//!
//! Wire format, from `block.cc`:
//!
//! * a graph is `<block index=N>` (`ELEM_BLOCK` 103, `ATTRIB_INDEX` 10)
//!   whose body is one `<bhead index=i type=NAME>` (`ELEM_BHEAD` 102,
//!   `ATTRIB_TYPE` 22) per component, then each component's own `<block>`;
//! * a component is a `plain` block. Not `copy`: `BlockMap::resolveBlock`
//!   decodes `t_copy` as `BlockCopy(nullptr)`, and `CollapseStructure` asks a
//!   block for its split point when it structures a loop
//!   (`BlockCopy::getSplitPoint` forwards to that null pointer), which kills
//!   the process on any cyclic graph. `t_plain` answers for itself;
//! * edges are recorded on the *destination*: `<edge end=SRC rev=POS>`
//!   (`ELEM_EDGE` 105, `ATTRIB_END` 77, `ATTRIB_REV` 79), where `end` is the
//!   source block's index and `rev` is that edge's position in the source's
//!   out-edge list (`BlockEdge::encode`).

use crate::wire;

/// Element and attribute ids, from `block.cc:22-31` and `marshal.cc:1241`.
const ELEM_BHEAD: u32 = 102;
const ELEM_BLOCK: u32 = 103;
const ELEM_EDGE: u32 = 105;
const ATTRIB_INDEX: u32 = 10;
const ATTRIB_TYPE: u32 = 22;
const ATTRIB_ALTINDEX: u32 = 75;
const ATTRIB_END: u32 = 77;
const ATTRIB_REV: u32 = 79;

/// A control-flow graph to structure: basic blocks in index order, and edges
/// as `(source, destination)` index pairs in the order each source branches.
#[derive(Debug, Clone, Default)]
pub struct ControlFlow {
    /// One entry per basic block; the value is the block's start address,
    /// carried through as `altindex` so results can be attributed back.
    pub blocks: Vec<u64>,
    pub edges: Vec<(usize, usize)>,
}

/// One node of the structured hierarchy the decompiler returns.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StructuredBlock {
    /// `FlowBlock::typeToName`, plus `ifgoto`/`properif`/`ifelse` for the
    /// three shapes `BlockGraph::encodeBody` distinguishes.
    pub kind: String,
    pub index: i64,
    /// Present on `copy` blocks: the index of the input block it came from.
    pub altindex: Option<i64>,
    pub children: Vec<StructuredBlock>,
}

impl StructuredBlock {
    /// Every block in the hierarchy, parents before children.
    pub fn walk(&self, visit: &mut impl FnMut(&StructuredBlock)) {
        visit(self);
        for child in &self.children {
            child.walk(visit);
        }
    }

    /// Blocks that print an unstructured jump.
    ///
    /// `BlockGoto` (`goto`) and `BlockMultiGoto` (`multigoto`) are exactly
    /// the shapes `CollapseStructure` produces when it cannot structure an
    /// edge; `ifgoto` is a conditional whose body is a single goto
    /// (`BlockGraph::encodeBody` names a `t_if` of size 1 that way), and it
    /// prints one too.
    pub fn gotos(&self) -> usize {
        let mut count = 0;
        self.walk(&mut |block| {
            if matches!(block.kind.as_str(), "goto" | "multigoto" | "ifgoto") {
                count += 1;
            }
        });
        count
    }

    /// Count of each block kind, for reporting what a structuring produced.
    pub fn kinds(&self) -> std::collections::BTreeMap<String, usize> {
        let mut counts = std::collections::BTreeMap::new();
        self.walk(&mut |block| {
            *counts.entry(block.kind.clone()).or_insert(0) += 1;
        });
        counts
    }
}

fn open(out: &mut Vec<u8>, id: u32) {
    wire::encode_header(out, wire::ELEMENT_START, id);
}

fn close(out: &mut Vec<u8>, id: u32) {
    wire::encode_header(out, wire::ELEMENT_END, id);
}

/// Writes an attribute whose value is a non-negative integer, in the packed
/// grammar `PackedDecode` expects (type code 2, seven-bit groups). Every
/// index this module writes is non-negative by construction.
fn signed_attribute(out: &mut Vec<u8>, id: u32, value: i64) {
    wire::encode_attribute(
        out,
        id,
        wire::attr_type::POSITIVE_INT,
        u64::try_from(value).unwrap_or(0),
    );
}

fn string_attribute(out: &mut Vec<u8>, id: u32, value: &str) {
    wire::encode_string_attribute(out, id, value.as_bytes());
}

impl ControlFlow {
    /// Encodes this graph the way `BlockGraph::encode` would, so
    /// `StructureGraph::loadParameters` can decode it.
    pub fn encode(&self) -> Vec<u8> {
        // Out-edge position per source, which is what `rev` records.
        let mut out_position: Vec<Vec<usize>> = vec![Vec::new(); self.blocks.len()];
        for (position, (source, _)) in self.edges.iter().enumerate() {
            if let Some(list) = out_position.get_mut(*source) {
                list.push(position);
            }
        }
        let mut reverse = vec![0usize; self.edges.len()];
        for list in &out_position {
            for (slot, edge) in list.iter().enumerate() {
                reverse[*edge] = slot;
            }
        }

        let mut doc = Vec::with_capacity(64 + self.blocks.len() * 24);
        open(&mut doc, ELEM_BLOCK);
        signed_attribute(&mut doc, ATTRIB_INDEX, 0);
        for index in 0..self.blocks.len() {
            open(&mut doc, ELEM_BHEAD);
            signed_attribute(&mut doc, ATTRIB_INDEX, index as i64);
            string_attribute(&mut doc, ATTRIB_TYPE, "plain");
            close(&mut doc, ELEM_BHEAD);
        }
        for (index, _) in self.blocks.iter().enumerate() {
            open(&mut doc, ELEM_BLOCK);
            signed_attribute(&mut doc, ATTRIB_INDEX, index as i64);
            for (position, (source, destination)) in self.edges.iter().enumerate() {
                if *destination != index {
                    continue;
                }
                open(&mut doc, ELEM_EDGE);
                signed_attribute(&mut doc, ATTRIB_END, *source as i64);
                signed_attribute(&mut doc, ATTRIB_REV, reverse[position] as i64);
                close(&mut doc, ELEM_EDGE);
            }
            close(&mut doc, ELEM_BLOCK);
        }
        close(&mut doc, ELEM_BLOCK);
        doc
    }
}

/// Decodes the `<block>` hierarchy `StructureGraph::rawAction` returns.
///
/// The type of a block is written by its *parent*'s `bhead` list, so a
/// child's kind is known before the child element is read; the outermost
/// block has no parent and is the graph itself.
pub fn decode(packed: &[u8]) -> Option<StructuredBlock> {
    let mut position = 0usize;
    let mut root = read_block(packed, &mut position, "graph".to_string())?;
    // A one-block graph is returned as that block, not as a graph of one.
    if root.kind == "graph" && root.children.len() == 1 && root.index == 0 {
        // Keep the graph node: callers count kinds, and collapsing it would
        // lose the distinction between "structured into one block" and "was
        // one block".
    }
    root.children.shrink_to_fit();
    Some(root)
}

fn read_block(packed: &[u8], position: &mut usize, kind: String) -> Option<StructuredBlock> {
    let header = *packed.get(*position)?;
    if header & 0xc0 != 0x40 {
        return None;
    }
    *position += 1;
    let id = read_id(packed, position, header)?;
    if id != ELEM_BLOCK {
        return None;
    }
    let mut block = StructuredBlock {
        kind,
        index: 0,
        altindex: None,
        children: Vec::new(),
    };
    // Attributes of this block, then its body: a list of `bhead` children,
    // the children themselves, and its in-edges.
    let mut pending: Vec<String> = Vec::new();
    loop {
        let header = *packed.get(*position)?;
        match header & 0xc0 {
            0xc0 => {
                *position += 1;
                let attribute = read_id(packed, position, header)?;
                let value = read_value(packed, position)?;
                match (attribute, value) {
                    (ATTRIB_INDEX, Value::Signed(value)) => block.index = value,
                    (ATTRIB_ALTINDEX, Value::Signed(value)) => block.altindex = Some(value),
                    _ => {}
                }
            }
            0x40 => {
                let mut lookahead = *position;
                lookahead += 1;
                let id = read_id(packed, &mut lookahead, header)?;
                match id {
                    ELEM_BHEAD => {
                        *position = lookahead;
                        let mut kind = String::new();
                        loop {
                            let header = *packed.get(*position)?;
                            if header & 0xc0 == 0xc0 {
                                *position += 1;
                                let attribute = read_id(packed, position, header)?;
                                let value = read_value(packed, position)?;
                                if attribute == ATTRIB_TYPE {
                                    if let Value::String(name) = value {
                                        kind = name;
                                    }
                                }
                            } else {
                                break;
                            }
                        }
                        // Element end for the bhead.
                        let header = *packed.get(*position)?;
                        if header & 0xc0 != 0x80 {
                            return None;
                        }
                        *position += 1;
                        read_id(packed, position, header)?;
                        pending.push(kind);
                    }
                    ELEM_BLOCK => {
                        let kind = if pending.is_empty() {
                            "plain".to_string()
                        } else {
                            pending.remove(0)
                        };
                        let child = read_block(packed, position, kind)?;
                        block.children.push(child);
                    }
                    // Anything else is a leaf element this side does not
                    // model -- `<edge>`, and `<target>` on a goto block,
                    // which names where the unstructured jump goes. Skipped
                    // whole, so an upstream addition cannot make a result
                    // undecodable: the kinds and the shape are what is read.
                    _ => skip_element(packed, position)?,
                }
            }
            0x80 => {
                *position += 1;
                read_id(packed, position, header)?;
                return Some(block);
            }
            _ => return None,
        }
    }
}

enum Value {
    Signed(i64),
    Unsigned(u64),
    String(String),
    Other,
}

/// Consumes one element and everything inside it.
fn skip_element(packed: &[u8], position: &mut usize) -> Option<()> {
    let mut depth = 0usize;
    loop {
        let header = *packed.get(*position)?;
        *position += 1;
        match header & 0xc0 {
            0x40 => {
                read_id(packed, position, header)?;
                depth += 1;
            }
            0x80 => {
                read_id(packed, position, header)?;
                depth -= 1;
                if depth == 0 {
                    return Some(());
                }
            }
            0xc0 => {
                read_id(packed, position, header)?;
                read_value(packed, position)?;
            }
            _ => return None,
        }
    }
}

fn read_id(packed: &[u8], position: &mut usize, header: u8) -> Option<u32> {
    let mut id = (header & 0x1f) as u32;
    if header & 0x20 != 0 {
        id = (id << 7) | (*packed.get(*position)? & 0x7f) as u32;
        *position += 1;
    }
    Some(id)
}

fn read_groups(packed: &[u8], position: &mut usize, groups: usize) -> Option<u64> {
    let mut value = 0u64;
    for _ in 0..groups {
        value = value
            .checked_mul(128)?
            .checked_add((*packed.get(*position)? & 0x7f) as u64)?;
        *position += 1;
    }
    Some(value)
}

fn read_value(packed: &[u8], position: &mut usize) -> Option<Value> {
    let type_byte = *packed.get(*position)?;
    *position += 1;
    let groups = (type_byte & 0x0f) as usize;
    match type_byte >> 4 {
        1 => Some(Value::Other),
        2 => Some(Value::Signed(
            i64::try_from(read_groups(packed, position, groups)?).ok()?,
        )),
        3 => Some(Value::Signed(
            i64::try_from(read_groups(packed, position, groups)?)
                .ok()?
                .checked_neg()?,
        )),
        4 => Some(Value::Unsigned(read_groups(packed, position, groups)?)),
        7 => {
            let length = usize::try_from(read_groups(packed, position, groups)?).ok()?;
            let bytes = packed.get(*position..position.checked_add(length)?)?;
            *position += length;
            Some(Value::String(String::from_utf8_lossy(bytes).into_owned()))
        }
        _ => {
            read_groups(packed, position, groups)?;
            Some(Value::Other)
        }
    }
}
