//! A decompressed `.sla` shared between decoders, and the lazily decoded
//! parts of a language built on it.
//!
//! (romwright addition, not in the C++ or upstream Rust port; see
//! `docs/third-party.md`.)
//!
//! Decoding a language's `.sla` into objects costs tens of megabytes per
//! decoder for x86-64 and nearly all of it is never read by one program:
//! constructor templates (57% of the decoded heap), decision trees and the
//! constructors themselves are looked up by the few instructions a program
//! uses. Every decoder of a process decodes the same file, and its tables
//! are `Rc`-linked to its own address spaces so they cannot be shared
//! between threads. What can be shared is the *bytes*, and what each decoder
//! can avoid is the objects it never reads.
//!
//! [`SlaImage::parse`] inflates the file once and cuts three kinds of
//! element out of the packed stream into one shared `bodies` buffer:
//! every `constructor` (with the `construct_tpl` elements inside it), every
//! subtable's root `decision` (with its descendants inside it). The
//! `skeleton` the eager decode reads keeps a *stub* of each (start record,
//! attributes, end record). The tables record where every constructor,
//! template and decision node is, so a decoder keeps only an empty slot per
//! item and decodes an item the first time it is used.
//!
//! The image is plain bytes and offsets: it is `Send + Sync`, shared by every
//! decoder of the language through an `Arc`, and its size is paid once per
//! process, not once per decoder.

use std::cell::OnceCell;
use std::sync::Arc;

use kuna_base::compression::Decompress;
use kuna_base::error::{KunaError, KunaResult};
use kuna_base::marshal::Decoder;
use kuna_base::marshal::PackedDecode;
use kuna_base::space::AddrSpaceManager;

use crate::semantics::ConstructTpl;
use crate::slaformat as sla;
use crate::slghpattern::DisjointPattern;
use crate::slghpatexpress::OperandValueResolver;
use crate::slghsymbol::{Constructor, ConstructTplHandle, SleighBaseTrans};

/// An inflated `.sla` with its constructors, templates and decision trees
/// cut out.
#[derive(Debug)]
pub struct SlaImage {
    /// The packed stream with each constructor and root decision reduced to
    /// its stub.
    skeleton: Vec<u8>,
    /// The cut-out elements, whole, back to back.
    bodies: Vec<u8>,
    /// Each constructor, in stream order: `(offset, length, first template)`.
    constructors: Vec<(u32, u32, u32)>,
    /// Each `construct_tpl`, in stream order, by handle: `(offset, length)`.
    templates: Vec<(u32, u32)>,
    /// Each `decision` element, preorder: `(offset, length, elements in its
    /// subtree including itself)`.
    decisions: Vec<(u32, u32, u32)>,
    /// The decision index of each subtable's root, in stream order.
    roots: Vec<u32>,
}

const ELEMENT_START: u8 = 0x40;
const ELEMENT_END: u8 = 0x80;
const ATTRIBUTE: u8 = 0xc0;
const HEADER_MASK: u8 = 0xc0;
const EXTEND: u8 = 0x20;
const ID_MASK: u8 = 0x1f;

fn bad(message: &str) -> KunaError {
    KunaError::lowlevel(message.to_string())
}

#[derive(Clone, Copy)]
enum Frame {
    Other,
    /// A cut-out element (constructor or root decision): where its record
    /// started.
    Top { start: usize },
    Template { index: usize, start: usize },
    Decision { index: usize, start: usize },
}

impl SlaImage {
    /// Inflates `sla` (a whole `.sla` file) and splits it.
    pub fn parse(sla_bytes: &[u8]) -> KunaResult<SlaImage> {
        let (ok, compressed) = sla::is_sla_format(sla_bytes);
        if !ok {
            return Err(KunaError::lowlevel("Missing SLA format header"));
        }
        let mut decompressor = Decompress::new();
        let mut data: Vec<u8> = Vec::with_capacity(compressed.len() * 10);
        decompressor.input(compressed);
        const CHUNK: usize = 64 * 1024;
        let mut buf = vec![0u8; CHUNK];
        while !decompressor.is_finished() {
            let avail = decompressor.inflate(&mut buf)?;
            let produced = CHUNK - avail as usize;
            data.extend_from_slice(&buf[..produced]);
            if produced == 0 && !decompressor.is_finished() {
                return Err(KunaError::lowlevel("Truncated SLA compressed stream"));
            }
        }
        drop(buf);
        Self::split(data)
    }

    /// Cuts the constructors and root decisions out of an inflated packed
    /// stream and indexes what is inside them.
    fn split(mut data: Vec<u8>) -> KunaResult<SlaImage> {
        let constructor_id = sla::ELEM_CONSTRUCTOR.get_id();
        let template_id = sla::ELEM_CONSTRUCT_TPL.get_id();
        let decision_id = sla::ELEM_DECISION.get_id();
        let subtable_id = sla::ELEM_SUBTABLE_SYM.get_id();
        // The stream ends at its first NUL byte (every packed byte has its
        // high bit set), as `PackedDecode::ingest_stream` reads it.
        let length = data.iter().position(|&byte| byte == 0).unwrap_or(data.len());
        let mut skeleton: Vec<u8> = Vec::with_capacity(length / 4);
        // Where the cut-out elements will sit once packed together at the
        // front of `data`, and where they are now.
        let mut packed = 0usize;
        let mut cuts: Vec<(usize, usize)> = Vec::new();
        let mut image = SlaImage {
            skeleton: Vec::new(),
            bodies: Vec::new(),
            constructors: Vec::new(),
            templates: Vec::new(),
            decisions: Vec::new(),
            roots: Vec::new(),
        };
        let mut copied = 0usize;
        let mut stack: Vec<(u32, Frame)> = Vec::new();
        // The cut-out element being walked: where it began in the stream,
        // where it lands in `bodies`, and where its attributes end.
        let mut cut: Option<(usize, usize, Option<usize>)> = None;
        let mut pos = 0usize;
        let truncated = || bad("Truncated SLA packed stream");
        let offset_of = |value: usize| u32::try_from(value).map_err(|_| bad("SLA stream exceeds 4 GiB"));
        while pos < length {
            let record = pos;
            let header = data[pos];
            pos += 1;
            let mut id = u32::from(header & ID_MASK);
            if header & EXTEND != 0 {
                let low = *data.get(pos).ok_or_else(truncated)?;
                pos += 1;
                id = (id << 7) | u32::from(low & 0x7f);
            }
            match header & HEADER_MASK {
                ELEMENT_START => {
                    let parent = stack.last().map(|frame| frame.0);
                    let frame = match &mut cut {
                        Some((cut_start, base, attributes_end)) => {
                            if attributes_end.is_none() {
                                *attributes_end = Some(record);
                            }
                            let offset = offset_of(*base + (record - *cut_start))?;
                            if id == template_id {
                                image.templates.push((offset, 0));
                                Frame::Template { index: image.templates.len() - 1, start: record }
                            } else if id == decision_id {
                                image.decisions.push((offset, 0, 0));
                                Frame::Decision { index: image.decisions.len() - 1, start: record }
                            } else {
                                Frame::Other
                            }
                        }
                        None => {
                            if id == constructor_id {
                                image.constructors.push((offset_of(packed)?, 0, offset_of(image.templates.len())?));
                                cut = Some((record, packed, None));
                                Frame::Top { start: record }
                            } else if id == decision_id && parent == Some(subtable_id) {
                                image.roots.push(offset_of(image.decisions.len())?);
                                image.decisions.push((offset_of(packed)?, 0, 0));
                                cut = Some((record, packed, None));
                                Frame::Top { start: record }
                            } else {
                                Frame::Other
                            }
                        }
                    };
                    stack.push((id, frame));
                }
                ELEMENT_END => {
                    let (closed, frame) = stack.pop().ok_or_else(|| bad("Unbalanced SLA packed stream"))?;
                    match frame {
                        Frame::Other => {}
                        Frame::Template { index, start } => {
                            image.templates[index].1 = offset_of(pos - start)?;
                        }
                        Frame::Decision { index, start } => {
                            let subtree = offset_of(image.decisions.len() - index)?;
                            let entry = &mut image.decisions[index];
                            entry.1 = offset_of(pos - start)?;
                            entry.2 = subtree;
                        }
                        Frame::Top { start } => {
                            let (_, _, attributes_end) = cut.take().expect("a cut element is open");
                            let attributes_end = attributes_end.unwrap_or(record);
                            skeleton.extend_from_slice(&data[copied..attributes_end]);
                            skeleton.push(ELEMENT_END | (header & 0x3f));
                            if header & EXTEND != 0 {
                                skeleton.push(data[record + 1]);
                            }
                            let size = offset_of(pos - start)?;
                            cuts.push((start, pos));
                            packed += pos - start;
                            copied = pos;
                            if closed == constructor_id {
                                image.constructors.last_mut().expect("opened above").1 = size;
                            } else {
                                // A root decision: its entry is the last one
                                // opened before its descendants, found by root
                                // index.
                                let index = *image.roots.last().expect("opened above") as usize;
                                let subtree = offset_of(image.decisions.len() - index)?;
                                let entry = &mut image.decisions[index];
                                entry.1 = size;
                                entry.2 = subtree;
                            }
                        }
                    }
                }
                ATTRIBUTE => {
                    let type_byte = *data.get(pos).ok_or_else(truncated)?;
                    pos += 1;
                    let kind = type_byte >> 4;
                    if kind != 1 && kind != 6 {
                        let mut size = usize::from(type_byte & 0x0f);
                        if kind == 7 {
                            let mut length_of_string = 0usize;
                            for _ in 0..size {
                                let byte = *data.get(pos).ok_or_else(truncated)?;
                                pos += 1;
                                length_of_string = (length_of_string << 7) | usize::from(byte & 0x7f);
                            }
                            size = length_of_string;
                        }
                        pos = pos.checked_add(size).filter(|end| *end <= length).ok_or_else(truncated)?;
                    }
                }
                _ => return Err(bad("Bad record in SLA packed stream")),
            }
        }
        if !stack.is_empty() || cut.is_some() {
            return Err(truncated());
        }
        skeleton.extend_from_slice(&data[copied..length]);
        skeleton.shrink_to_fit();
        // Pack the cut elements to the front of the inflated stream, in
        // order (each moves down, never over one still to move), and keep
        // that as the bodies: no second copy of them is ever held.
        let mut at = 0usize;
        for (start, end) in cuts {
            data.copy_within(start..end, at);
            at += end - start;
        }
        data.truncate(at);
        data.shrink_to_fit();
        let bodies = data;
        image.constructors.shrink_to_fit();
        image.templates.shrink_to_fit();
        image.decisions.shrink_to_fit();
        image.roots.shrink_to_fit();
        image.skeleton = skeleton;
        image.bodies = bodies;
        Ok(image)
    }

    /// The stream the eager decode reads.
    pub(crate) fn skeleton(&self) -> &[u8] {
        &self.skeleton
    }

    /// Number of constructor templates the image carries.
    pub fn template_count(&self) -> usize {
        self.templates.len()
    }

    /// Number of constructors the image carries.
    pub fn constructor_count(&self) -> usize {
        self.constructors.len()
    }

    /// Bytes this image holds.
    pub fn resident_bytes(&self) -> usize {
        self.skeleton.len()
            + self.bodies.len()
            + self.constructors.len() * std::mem::size_of::<(u32, u32, u32)>()
            + self.templates.len() * std::mem::size_of::<(u32, u32)>()
            + self.decisions.len() * std::mem::size_of::<(u32, u32, u32)>()
            + self.roots.len() * 4
    }

    /// The global index of the next constructor / root decision a stub
    /// stands for is counted by the skeleton decode; these answer for it.
    pub(crate) fn root_decision(&self, root: usize) -> KunaResult<usize> {
        self.roots.get(root).map(|&index| index as usize).ok_or_else(|| bad("SLA stream has more decision stubs than roots"))
    }

    fn slice(&self, offset: u32, length: u32) -> &[u8] {
        &self.bodies[offset as usize..offset as usize + length as usize]
    }

    /// Decodes one element of `bodies` with `decode`, over an empty address
    /// space set: constructors and decision nodes name no space.
    fn with_decoder<R>(
        &self,
        manager: &AddrSpaceManager,
        offset: u32,
        length: u32,
        decode: impl FnOnce(&mut PackedDecode<'_>) -> KunaResult<R>,
    ) -> KunaResult<R> {
        let mut decoder = PackedDecode::new(manager);
        Decoder::ingest_stream(&mut decoder, self.slice(offset, length))?;
        decode(&mut decoder)
    }

    /// Constructor `index` (global), its templates left as handles.
    pub(crate) fn decode_constructor(&self, index: usize) -> KunaResult<Constructor> {
        let &(offset, length, first_template) = self
            .constructors
            .get(index)
            .ok_or_else(|| bad("SLA stream has more constructor stubs than constructors"))?;
        let mut trans = LazyConstructor { next_template: first_template as usize };
        let resolver = Unchecked;
        EMPTY_SPACES.with(|manager| {
            self.with_decoder(manager, offset, length, |decoder| Constructor::decode(decoder, &resolver, &mut trans))
        })
    }

    /// Template `handle` of the language.
    fn decode_template(&self, handle: usize, manager: &AddrSpaceManager) -> KunaResult<ConstructTpl> {
        let &(offset, length) = self.templates.get(handle).ok_or_else(|| bad("template handle out of range"))?;
        self.with_decoder(manager, offset, length, |decoder| {
            let mut template = ConstructTpl::new();
            template.decode(decoder)?;
            Ok(template)
        })
    }

    /// Decision node `index` (global, preorder) with its children left as
    /// indices.
    pub(crate) fn decode_decision(&self, index: usize) -> KunaResult<LazyNode> {
        let &(offset, length, _) = self.decisions.get(index).ok_or_else(|| bad("decision index out of range"))?;
        EMPTY_SPACES.with(|manager| {
            self.with_decoder(manager, offset, length, |decoder| {
                let el = decoder.open_element_id(&sla::ELEM_DECISION)?;
                let mut node = LazyNode {
                    contextdecision: false,
                    startbit: 0,
                    bitsize: 0,
                    list: Vec::new(),
                    children: Vec::new(),
                };
                let _num = decoder.read_signed_integer_id(&sla::ATTRIB_NUMBER)?;
                node.contextdecision = decoder.read_bool_id(&sla::ATTRIB_CONTEXT)?;
                node.startbit = decoder.read_signed_integer_id(&sla::ATTRIB_STARTBIT)? as i32;
                node.bitsize = decoder.read_signed_integer_id(&sla::ATTRIB_SIZE)? as i32;
                let mut next = index + 1;
                let mut subel = decoder.peek_element()?;
                while subel != 0 {
                    if subel == sla::ELEM_PAIR {
                        decoder.open_element()?;
                        let id = decoder.read_signed_integer_id(&sla::ATTRIB_ID)? as u32;
                        let pattern = DisjointPattern::decode_disjoint(decoder)?;
                        node.list.push((pattern, id));
                        decoder.close_element(subel)?;
                    } else if subel == sla::ELEM_DECISION {
                        let child = decoder.open_element()?;
                        decoder.close_element_skipping(child)?;
                        let &(_, _, subtree) = self.decisions.get(next).ok_or_else(|| bad("decision child out of range"))?;
                        node.children.push((next as u32, OnceCell::new()));
                        next += subtree as usize;
                    } else {
                        return Err(bad("unexpected element in a decision node"));
                    }
                    subel = decoder.peek_element()?;
                }
                decoder.close_element(el)?;
                node.list.shrink_to_fit();
                node.children.shrink_to_fit();
                Ok(node)
            })
        })
    }
}

thread_local! {
    /// The spaces constructors and decision nodes are decoded against: they
    /// name none.
    static EMPTY_SPACES: AddrSpaceManager = AddrSpaceManager::new();
}

/// What a constructor body needs of its decode context: the next template
/// handle (templates of a constructor are consecutive, in stream order) and
/// no operand validation (the stream was validated when the language was
/// built).
struct LazyConstructor {
    next_template: usize,
}

impl SleighBaseTrans for LazyConstructor {
    fn get_constant_space(&self) -> std::rc::Rc<kuna_base::space::AddrSpace> {
        unreachable!("a lazily decoded constructor names no constant space")
    }

    fn decode_construct_tpl(
        &mut self,
        decoder: &mut dyn kuna_num::opcodes::OpcodeDecoder,
    ) -> KunaResult<(i32, ConstructTplHandle)> {
        let el = decoder.open_element_id(&sla::ELEM_CONSTRUCT_TPL)?;
        let mut sectionid: i32 = -1;
        let mut attrib = decoder.get_next_attribute_id()?;
        while attrib != 0 {
            if attrib == sla::ATTRIB_SECTION {
                sectionid = decoder.read_signed_integer()? as i32; // C++ intb -> int4
            }
            attrib = decoder.get_next_attribute_id()?;
        }
        decoder.close_element_skipping(el)?;
        let handle = self.next_template;
        self.next_template += 1;
        Ok((sectionid, handle))
    }
}

/// Operand validation off: see [`LazyConstructor`].
struct Unchecked;

impl OperandValueResolver for Unchecked {
    fn num_constructors(&self, _table_id: u32) -> KunaResult<i32> {
        Ok(i32::MAX)
    }
}

/// A decision node of a lazily decoded subtable: its own terminal patterns
/// and the indices of its children, which are decoded when a decode reaches
/// them.
#[derive(Debug, Clone)]
pub struct LazyNode {
    list: Vec<(DisjointPattern, u32)>,
    children: Vec<(u32, OnceCell<Box<LazyNode>>)>,
    contextdecision: bool,
    startbit: i32,
    bitsize: i32,
}

impl LazyNode {
    /// `DecisionNode::resolve_matched` over a tree decoded as it is walked.
    pub fn resolve_matched<'a>(
        &'a self,
        walker: &dyn crate::slghsymbol::SymbolWalker,
        image: &SlaImage,
    ) -> KunaResult<&'a (DisjointPattern, u32)> {
        let mut node = self;
        loop {
            if node.bitsize == 0 {
                let pw: &dyn crate::slghpatexpress::PatternExpressionContext = walker;
                for pair in &node.list {
                    if pair.0.is_match(pw)? {
                        return Ok(pair);
                    }
                }
                let mut s = String::new();
                s.push(walker.get_addr().get_shortcut());
                walker.get_addr().print_raw(&mut s)?;
                s.push_str(": Unable to resolve constructor");
                return Err(KunaError::bad_data(s));
            }
            let val = if node.contextdecision {
                walker.get_context_bits(node.startbit, node.bitsize)?
            } else {
                walker.get_instruction_bits(node.startbit, node.bitsize)?
            };
            let (index, cell) = node.children.get(val as usize).ok_or_else(|| bad("decision child out of range"))?;
            node = match cell.get() {
                Some(child) => child,
                None => {
                    let child = Box::new(image.decode_decision(*index as usize)?);
                    let _ = cell.set(child);
                    cell.get().expect("just set")
                }
            };
        }
    }
}

/// A subtable decoded as it is used: the constructors and the decision tree
/// are in the image, and this holds an empty slot for each.
#[derive(Debug, Clone)]
pub struct LazySubtable {
    image: Arc<SlaImage>,
    first_constructor: usize,
    constructors: Vec<OnceCell<Box<Constructor>>>,
    root: Option<(usize, OnceCell<Box<LazyNode>>)>,
}

impl LazySubtable {
    pub(crate) fn new(image: Arc<SlaImage>, first_constructor: usize, count: usize, root: Option<usize>) -> Self {
        LazySubtable {
            image,
            first_constructor,
            constructors: (0..count).map(|_| OnceCell::new()).collect(),
            root: root.map(|index| (index, OnceCell::new())),
        }
    }

    pub fn num_constructors(&self) -> usize {
        self.constructors.len()
    }

    pub fn constructor(&self, id: u32) -> Option<KunaResult<&Constructor>> {
        let cell = self.constructors.get(id as usize)?;
        if let Some(found) = cell.get() {
            return Some(Ok(found));
        }
        Some(match self.image.decode_constructor(self.first_constructor + id as usize) {
            Ok(mut constructor) => {
                constructor.set_id(id);
                let _ = cell.set(Box::new(constructor));
                Ok(&**cell.get().expect("just set"))
            }
            Err(error) => Err(error),
        })
    }

    /// The decision tree's root, decoded now if it was not.
    pub fn root(&self) -> Option<KunaResult<&LazyNode>> {
        let (index, cell) = self.root.as_ref()?;
        if let Some(found) = cell.get() {
            return Some(Ok(found));
        }
        Some(match self.image.decode_decision(*index) {
            Ok(node) => {
                let _ = cell.set(Box::new(node));
                Ok(&**cell.get().expect("just set"))
            }
            Err(error) => Err(error),
        })
    }

    pub fn image(&self) -> &SlaImage {
        &self.image
    }

    /// Constructors decoded so far.
    pub fn decoded_constructors(&self) -> usize {
        self.constructors.iter().filter(|cell| cell.get().is_some()).count()
    }
}

/// A function that turns a template into its marked variant.
pub type TemplateTransform = Box<dyn Fn(&mut ConstructTpl)>;

struct Slot {
    /// The template as the language has it, and as the transform makes it;
    /// each decoded the first time it is asked for.
    cells: [OnceCell<Box<ConstructTpl>>; 2],
    /// Whether the template is the image's (decoded on first use) or was
    /// pushed whole.
    lazy: bool,
}

/// The constructor templates of a language, by handle.
///
/// Handles `0..n` are the image's templates (decoded on first use and kept);
/// templates pushed whole (the compiler side) follow them.
///
/// A language's templates come in two variants for the one decoder: as the
/// language has them, and as a *marked transform* rewrites them (the flow
/// decoder's markers, `native_runtime/flow.rs`). Which one a decode reads is
/// a switch on the arena ([`TemplateArena::set_marked`]), so one decoder, one
/// set of tables, serves a flow lane and a plain lifter in turn.
#[derive(Default)]
pub struct TemplateArena {
    slots: Vec<Slot>,
    image: Option<Arc<SlaImage>>,
    transform: Option<TemplateTransform>,
    marked: std::cell::Cell<bool>,
}

impl std::fmt::Debug for TemplateArena {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TemplateArena").field("len", &self.slots.len()).field("decoded", &self.decoded()).finish()
    }
}

impl TemplateArena {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.slots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Templates decoded so far (either variant).
    pub fn decoded(&self) -> usize {
        self.slots.iter().filter(|slot| slot.cells.iter().any(|cell| cell.get().is_some())).count()
    }

    /// Adds a whole template, returning its handle.
    pub fn push(&mut self, template: ConstructTpl) -> ConstructTplHandle {
        let handle = self.slots.len();
        self.slots.push(Slot { cells: [OnceCell::from(Box::new(template)), OnceCell::new()], lazy: false });
        handle
    }

    /// Makes the arena the image's: one empty slot per template, handles in
    /// the image's order. Only on an empty arena.
    pub(crate) fn adopt_image(&mut self, image: Arc<SlaImage>) {
        debug_assert!(self.slots.is_empty());
        self.slots = (0..image.template_count()).map(|_| Slot { cells: [OnceCell::new(), OnceCell::new()], lazy: true }).collect();
        self.image = Some(image);
    }

    /// Installs the transform that makes the marked variant (once: a second
    /// call changes nothing).
    pub fn set_marked_transform(&mut self, transform: TemplateTransform) {
        if self.transform.is_none() {
            self.transform = Some(transform);
        }
    }

    /// Whether a marked transform is installed.
    pub fn has_marked_transform(&self) -> bool {
        self.transform.is_some()
    }

    /// Which variant reads see from here on. Marked needs a transform.
    pub fn set_marked(&self, marked: bool) {
        self.marked.set(marked && self.transform.is_some());
    }

    fn materialize<'a>(&'a self, handle: usize, manager: &AddrSpaceManager) -> &'a ConstructTpl {
        let slot = &self.slots[handle];
        let variant = usize::from(self.marked.get());
        slot.cells[variant].get_or_init(|| {
            let decode = || {
                let image = self.image.as_ref().expect("a lazy template has an image");
                image
                    .decode_template(handle, manager)
                    .unwrap_or_else(|error| panic!("constructor template {handle} of the .sla does not decode: {error}"))
            };
            let mut template = if variant == 0 {
                debug_assert!(slot.lazy);
                decode()
            } else if slot.lazy {
                decode()
            } else {
                (**slot.cells[0].get().expect("a template pushed whole is in the first cell")).clone()
            };
            if variant == 1 {
                (self.transform.as_ref().expect("the marked variant has a transform"))(&mut template);
            }
            Box::new(template)
        })
    }

    /// The template at `handle`, in the current variant, decoded now if it
    /// was not (C++ `getTempl`). Panics, as an out-of-range index does, when
    /// `handle` is not one this arena issued or a template's bytes are
    /// damaged.
    pub fn get(&self, handle: usize, manager: &AddrSpaceManager) -> &ConstructTpl {
        self.materialize(handle, manager)
    }

    /// Mutable access to a template as the language has it (the compiler
    /// side).
    pub fn get_mut(&mut self, handle: usize, manager: &AddrSpaceManager) -> Option<&mut ConstructTpl> {
        if handle >= self.slots.len() {
            return None;
        }
        let marked = self.marked.replace(false);
        self.materialize(handle, manager);
        self.marked.set(marked);
        self.slots[handle].cells[0].get_mut().map(|boxed| &mut **boxed)
    }

    /// Every template, decoded, as an owned list (the encoder's view), as the
    /// language has them.
    pub fn to_vec(&self, manager: &AddrSpaceManager) -> Vec<ConstructTpl> {
        let marked = self.marked.replace(false);
        let all = (0..self.slots.len()).map(|handle| self.materialize(handle, manager).clone()).collect();
        self.marked.set(marked);
        all
    }
}
