//! Semantic projection of the existing packed decoder, not a C-token parser.
use crate::{doc::Value, prototype::Node};
use romwright_model::function_ir::*;
use romwright_model::{Address, AddressSpace};
use std::collections::BTreeMap;

const AST: u32 = 115;
const HIGHLIST: u32 = 117;
const VARNODES: u32 = 119;
const BLOCK: u32 = 103;
const BLOCKEDGE: u32 = 104;
const EDGE: u32 = 105;

#[derive(Default)]
pub(crate) struct Collector {
    function_depth: Option<usize>,
    capture: Vec<Node>,
    ast: Option<Node>,
    high: Option<Node>,
    error: Option<String>,
    projections: Vec<Node>,
}
impl Collector {
    pub(crate) fn start(&mut self, id: u32, parent: Option<u32>, depth: usize) {
        if id == 116 && parent == Some(229) {
            self.function_depth = Some(depth);
        }
        let root = (matches!(id, AST | HIGHLIST)
            && self.function_depth == depth.checked_sub(1))
            || (id == BLOCKEDGE && parent == Some(229));
        if root || !self.capture.is_empty() {
            if self.capture.len() >= 64 {
                self.error = Some("semantic tree exceeds nesting bound".into());
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
        let Some(node) = self.capture.last_mut() else {
            return Some(value);
        };
        if node.depth == depth {
            if node.value(id).is_some() {
                self.error = Some("duplicate semantic attribute".into());
            }
            node.attributes.push((id, value));
        }
        None
    }
    pub(crate) fn end(&mut self, id: u32, depth: usize) {
        if self.capture.last().is_some_and(|node| node.depth == depth) {
            let node = self.capture.pop().unwrap();
            if node.id != id {
                self.error = Some("mismatched semantic element".into());
            }
            if let Some(parent) = self.capture.last_mut() {
                parent.children.push(node);
            } else {
                if id == BLOCKEDGE {
                    self.projections.push(node);
                    return;
                }
                let slot = match id {
                    AST => &mut self.ast,
                    HIGHLIST => &mut self.high,
                    _ => return,
                };
                if slot.replace(node).is_some() {
                    self.error = Some("duplicate native semantic tree".into());
                }
            }
        }
        if id == 116 && self.function_depth == Some(depth) {
            self.function_depth = None;
        }
    }
    pub(crate) fn finish(
        self,
        complete: bool,
        ram: Option<u64>,
    ) -> Result<(Option<FunctionIr>, Vec<(ControlFlowCut, ControlFlowCut)>), String> {
        if !complete || !self.capture.is_empty() {
            return Err("incomplete packed semantic document".into());
        }
        if let Some(error) = self.error {
            return Err(error);
        }
        let projections = self.projections.into_iter().map(|node| {
            let mut children = node.children.into_iter();
            let original = projected_cut(children.next().ok_or("missing original cut")?)?;
            let projected = projected_cut(children.next().ok_or("missing projected cut")?)?;
            if children.next().is_some() {
                return Err("extra cut projection element".into());
            }
            Ok((original, projected))
        }).collect::<Result<_, String>>()?;
        Ok((self.ast.map(|ast| decode(ast, self.high, ram)).transpose()?, projections))
    }
}

fn projected_cut(node: Node) -> Result<ControlFlowCut, String> {
    if node.id != EDGE || !node.children.is_empty() {
        return Err("invalid cut projection element".into());
    }
    Ok(ControlFlowCut {
        source: BlockId(number(&node, 10)?),
        successor_slot: usize::try_from(number(&node, 79)?)
            .map_err(|_| "cut slot overflow")?,
        target: BlockId(number(&node, 77)?),
    })
}

fn number(node: &Node, id: u32) -> Result<u64, String> {
    node.unsigned(id)
        .ok_or_else(|| format!(
            "missing integer attribute {id} on element {} (attributes: {:?})",
            node.id, node.attributes
        ))
}
fn flag(node: &Node, id: u32) -> Result<bool, String> {
    node.boolean(id)
        .ok_or_else(|| format!("invalid boolean attribute {id}"))
}
fn space(node: &mut Node, id: u32) -> Result<IrSpace, String> {
    let index = node
        .attributes
        .iter()
        .position(|(key, _)| *key == id)
        .ok_or_else(|| format!("missing address space on element {}", node.id))?;
    match node.attributes.swap_remove(index).1 {
        Value::Space(index) | Value::Unsigned(index) => Ok(IrSpace::Index(index)),
        Value::Special(index) => Ok(IrSpace::Special(index)),
        Value::String(name) => Ok(IrSpace::Named(name)),
        _ => Err("invalid semantic address space".into()),
    }
}
fn storage_pieces(node: &Node) -> Result<Vec<StoragePiece>, String> {
    let mut pieces = BTreeMap::new();
    for (id, attribute) in &node.attributes {
        if (94..159).contains(id) {
            let Value::String(text) = attribute else {
                return Err("invalid joined-storage piece".into());
            };
            let mut parts = text.rsplitn(3, ':');
            let size = parts
                .next()
                .and_then(|s| s.parse::<u32>().ok())
                .ok_or("invalid piece size")?;
            let offset = parts
                .next()
                .and_then(|s| s.strip_prefix("0x"))
                .and_then(|s| u64::from_str_radix(s, 16).ok())
                .ok_or("invalid piece offset")?;
            let name = parts.next().ok_or("missing piece space")?;
            pieces.insert(
                *id - 94,
                StoragePiece {
                    space: name.into(),
                    offset,
                    size,
                },
            );
        }
    }
    if pieces.keys().copied().ne(0..pieces.len() as u32) {
        return Err("missing joined-storage piece".into());
    }
    Ok(pieces.into_values().collect())
}
fn value(mut node: Node) -> Result<IrValue, String> {
    let pieces = storage_pieces(&node)?;
    let size = if pieces.is_empty() {
        node.unsigned(19)
            .map(|size| u32::try_from(size).map_err(|_| "value width overflow"))
            .transpose()?
    } else {
        Some(match node.unsigned(92) {
            Some(size) => u32::try_from(size).map_err(|_| "logical width overflow")?,
            None => pieces
                .iter()
                .try_fold(0u32, |sum, piece| sum.checked_add(piece.size))
                .ok_or("joined width overflow")?,
        })
    };
    Ok(IrValue {
        id: ValueId(number(&node, 18)?),
        space: space(&mut node, 20)?,
        offset: node.unsigned(16),
        size,
        pieces,
        input: flag(&node, 32)?,
        persistent: flag(&node, 33)?,
        address_tied: flag(&node, 30)?,
        unaffected: flag(&node, 34)?,
        volatile: flag(&node, 65)?,
    })
}
fn operand(mut node: Node) -> Result<Operand, String> {
    match node.id {
        11 => Ok(Operand::Value(ValueId(number(&node, 18)?))),
        113 => Ok(Operand::Operation(OperationId(number(&node, 25)?))),
        30 => Ok(Operand::Space(space(&mut node, 14)?)),
        10 => Ok(Operand::Void),
        _ => Err(format!("unknown operation operand element {}", node.id)),
    }
}
pub(crate) fn address(mut node: Node, ram: Option<u64>) -> Result<Address, String> {
    let offset = number(&node, 16)?;
    let space = match space(&mut node, 20)? {
        IrSpace::Index(index) if Some(index) == ram => AddressSpace::Ram,
        IrSpace::Index(index) => AddressSpace::Other(format!("space:{index}")),
        IrSpace::Named(name) => AddressSpace::Other(name),
        IrSpace::Special(index) => AddressSpace::Other(format!("special:{index}")),
    };
    Ok(Address { space, offset })
}
fn operation(node: Node, ram: Option<u64>) -> Result<IrOperation, String> {
    let opcode = Opcode::try_from(number(&node, 43)?)?;
    let mut children = node.children.into_iter();
    let sequence = children
        .next()
        .filter(|node| node.id == 15)
        .ok_or("missing operation sequence")?;
    let id = OperationId(number(&sequence, 29)?);
    let address = address(sequence, ram)?;
    let output = match operand(children.next().ok_or("missing output slot")?)? {
        Operand::Value(value) => Some(value),
        Operand::Void => None,
        _ => return Err("invalid operation output slot".into()),
    };
    Ok(IrOperation {
        id,
        address,
        opcode,
        output,
        inputs: children.map(operand).collect::<Result<_, _>>()?,
    })
}
fn decode(mut ast: Node, high: Option<Node>, ram: Option<u64>) -> Result<FunctionIr, String> {
    let varnodes = ast.take_child(VARNODES).ok_or("missing SSA values")?;
    let mut values = BTreeMap::new();
    for node in varnodes.children {
        if node.id != 11 {
            return Err("invalid SSA value element".into());
        }
        let value = value(node)?;
        if values.insert(value.id, value).is_some() {
            return Err("duplicate SSA value".into());
        }
    }
    let mut blocks = Vec::new();
    let mut edges = Vec::new();
    for node in ast.children {
        match node.id {
            BLOCK => blocks.push(IrBlock {
                id: BlockId(number(&node, 10)?),
                operations: node
                    .children
                    .into_iter()
                    .filter(|child| child.id == 27)
                    .map(|child| operation(child, ram))
                    .collect::<Result<_, _>>()?,
                predecessors: Vec::new(),
                successors: Vec::new(),
            }),
            BLOCKEDGE => edges.push(node),
            _ => return Err(format!("unknown syntax-tree element {}", node.id)),
        }
    }
    let index: BTreeMap<_, _> = blocks
        .iter()
        .enumerate()
        .map(|(index, block)| (block.id, index))
        .collect();
    let mut outgoing: BTreeMap<BlockId, BTreeMap<u64, BlockId>> = BTreeMap::new();
    let mut seen_edges = std::collections::BTreeSet::new();
    for edge_list in edges {
        let target = BlockId(number(&edge_list, 10)?);
        if !seen_edges.insert(target) {
            return Err("duplicate predecessor list".into());
        }
        let target_index = *index.get(&target).ok_or("missing edge destination")?;
        for edge in edge_list.children {
            if edge.id != EDGE {
                return Err("invalid CFG edge element".into());
            }
            let source = BlockId(number(&edge, 77)?);
            let slot = number(&edge, 79)?;
            blocks[target_index].predecessors.push(source);
            if outgoing
                .entry(source)
                .or_default()
                .insert(slot, target)
                .is_some()
            {
                return Err("duplicate outgoing edge slot".into());
            }
        }
    }
    for (source, targets) in outgoing {
        let block = &mut blocks[*index.get(&source).ok_or("missing edge source")?];
        for (expected, (slot, target)) in targets.into_iter().enumerate() {
            if slot != expected as u64 {
                return Err("missing outgoing edge slot".into());
            }
            block.successors.push(target);
        }
    }
    let mut high_variables = Vec::new();
    for mut node in high.into_iter().flat_map(|list| list.children) {
        if node.id != 82 {
            return Err("invalid high-variable element".into());
        }
        let symbol = if let Some(id) = node.unsigned(68) {
            let mut symbol = node
                .take_child(crate::wire::elem::SYMBOL)
                .ok_or("missing high-variable symbol metadata")?;
            let (location, pieces) = match symbol.take_child(crate::wire::elem::ADDR) {
                None => (None, Vec::new()),
                Some(mut storage) => {
                    let pieces = storage_pieces(&storage)?;
                    if pieces.is_empty() {
                        (Some(address(storage, ram)?), pieces)
                    } else {
                        // PackedFormat::SPECIALSPACE_JOIN is 1. A joined
                        // location carries ordered pieces, not an offset.
                        if space(&mut storage, 20)? != IrSpace::Special(1) {
                            return Err("symbol pieces require joined storage".into());
                        }
                        (None, pieces)
                    }
                }
            };
            Some(IrSymbol {
                id,
                name: symbol.string(14).ok_or("missing symbol name")?,
                data_type: symbol.take_type().ok_or("missing symbol type")?,
                volatile: flag(&symbol, 65)?,
                global: flag(&symbol, 33)?,
                address: location,
                pieces,
            })
        } else {
            None
        };
        high_variables.push(HighVariable {
            representative: ValueId(number(&node, 67)?),
            class: node.string(66).ok_or("missing high-variable class")?,
            symbol,
            symbol_offset: node.value(16).and_then(Value::signed),
            type_locked: flag(&node, 23)?,
            data_type: node.take_type().ok_or("missing high-variable type")?,
            members: node
                .children
                .into_iter()
                .filter(|child| child.id == 11)
                .map(|child| number(&child, 18).map(ValueId))
                .collect::<Result<_, _>>()?,
        });
    }
    let result = FunctionIr {
        values,
        blocks,
        high_variables,
        type_evidence: BTreeMap::new(),
        control_flow_cuts: Vec::new(),
        passes: Vec::new(),
        diagnostics: Vec::new(),
    };
    result.validate()?;
    Ok(result)
}
