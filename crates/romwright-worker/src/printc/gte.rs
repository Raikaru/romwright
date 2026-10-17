//! psyq-style GTE macro lifting over the printer IR (plan P4.1).
//!
//! The PSX language (`native/languages/psx`, `gte.sinc`) decodes COP2: a
//! register move or `lwc2`/`swc2` is a plain read or write of a named GTE
//! register (`VXY0 = *param_1;`, `*param_2 = SXY2;`) and a GTE command is one
//! named userop (`gte_rtps(1,0);`). The code a PlayStation program is
//! compiled from wrote none of that: it used one inline macro per step, a
//! load, a command, a store. This pass folds the statements of a basic block
//! back into one call per macro:
//!
//! ```text
//! VXY0 = *param_1;                 gte_ldv0(param_1);
//! VZ0 = (int)(short)param_1[1];    gte_RTPS();
//! gte_rtps(1,0);              =>   gte_stsxy(param_2);
//! *param_2 = SXY2;
//! ```
//!
//! # What is recognised
//!
//! * **Commands.** `gte_<command>(sf,lm)` becomes `gte_<COMMAND>()` (the
//!   command names are psx-spx's: RTPS, RTPT, NCLIP, AVSZ3, ...). The two
//!   flags print only when they are not `sf=1, lm=0`, the setting the
//!   geometry commands are normally issued with (`gte_NCDS(1,1)`); `NCLIP`,
//!   `AVSZ3` and `AVSZ4` take no flags and `MVMVA` prints all five fields.
//! * **Loads and stores through memory.** A `lwc2` is `GTE_REG = *p`, an
//!   `swc2` is `*p = GTE_REG`. A run of them becomes one call whose argument
//!   is the address: `gte_ldv0(p)` (`VXY0`, `VZ0` from `p`, `p+4`),
//!   `gte_ldv3(p0,p1,p2)`, `gte_ldsxy3`, `gte_stsxy3`, `gte_stlvnl(p)`, ...
//!   (the tables below). Any other data-register access is a one-register
//!   call named after the register (`gte_ldir1(p)`, `gte_stmac2(p)`).
//! * **Matrix and translation loads.** The five rotation, light or colour
//!   matrix control words loaded from one base become `gte_SetRotMatrix(p)`,
//!   `gte_SetLightMatrix(p)` or `gte_SetColorMatrix(p)`, and the three
//!   translation words at `p+20` become `gte_SetTransMatrix(p)`.
//!
//! A pass over text would see only what PrintC printed. This one reads each
//! statement's exported effect (what it writes, the address expression it
//! loads or stores through) to decide that statements belong together, and
//! takes the address operand's tokens from the statement's own fragment, so
//! the argument prints as Ghidra named it (`param_1`, `&param_1[1]`,
//! `&obj->field`). A run whose address is not a name, a deref, an element or
//! a field is left as written.
//!
//! Names. Command names, register names and the register-to-memory mapping
//! are psx-spx's. The macro names follow the register names with the
//! `ld`/`st` convention the PlayStation SDK's API uses; no SDK source or
//! header was read (docs/third-party.md, "PSX language").
//!
//! The pass is on by default and `ROMWRIGHT_GTE_MACROS=0` switches it off.
//! It changes nothing in a function without a GTE register or command, and
//! it runs on the decoded IR, so [`super::reference`] (the printer
//! differential) never sees it.

use super::ir::{
    Basic, CaseBody, Detail, Effect, Event, Expr, Expression, Fragment, Node, PrinterIr, Source,
    Statement,
};
use super::pretty::{CONST_COLOR, NO_COLOR};
use std::collections::{BTreeMap, HashMap, HashSet};

/// Environment switch: `0` prints the statements as they were.
pub const ENV: &str = "ROMWRIGHT_GTE_MACROS";

/// Whether the pass runs ([`ENV`] unset or not `0`).
pub fn enabled() -> bool {
    std::env::var_os(ENV).is_none_or(|value| value != "0")
}

/// `EmitMarkup::funcname_color`, the colour PrintC gives a userop call's name.
const FUNCNAME_COLOR: u8 = 3;
/// `OpToken::bump` of PrintC's `function_call` token.
const CALL_BUMP: i32 = 10;

// `PcodeOp::code` of the statements this pass reads (opcodes.hh).
const COPY: u32 = 1;
const LOAD: u32 = 2;
const STORE: u32 = 3;
const CALLOTHER: u32 = 9;
const INT_ZEXT: u32 = 17;
const INT_SEXT: u32 = 18;
const INT_ADD: u32 = 19;
const INT_SUB: u32 = 20;
const INT_AND: u32 = 27;
const SUBPIECE: u32 = 63;
const CAST: u32 = 64;
const PTRADD: u32 = 65;
const PTRSUB: u32 = 66;

/// What the pass did to one function.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct GteStats {
    /// Macro calls printed in place of statements, by macro name (commands
    /// included: the `gte_<cmd>(sf,lm)` userop calls renamed to `gte_CMD()`).
    pub macros: BTreeMap<String, u64>,
    /// Register loads and stores the load/store macros replaced.
    pub accesses_folded: u64,
    /// Register loads and stores left as written (no usable address, or a
    /// control register that no macro covers).
    pub accesses_left: u64,
}

impl GteStats {
    /// Macro calls in all.
    pub fn total(&self) -> u64 {
        self.macros.values().sum()
    }
}

// -- registers ---------------------------------------------------------------
//
// psx-spx "Geometry Transformation Engine (GTE)", register map: cop2r0-31 are
// the data registers, cop2r32-63 the control registers. A register is named by
// its index into DATA followed by CONTROL (0..64).

const DATA: [&str; 32] = [
    "VXY0", "VZ0", "VXY1", "VZ1", "VXY2", "VZ2", "RGBC", "OTZ", "IR0", "IR1", "IR2", "IR3",
    "SXY0", "SXY1", "SXY2", "SXYP", "SZ0", "SZ1", "SZ2", "SZ3", "RGB0", "RGB1", "RGB2", "RES1",
    "MAC0", "MAC1", "MAC2", "MAC3", "IRGB", "ORGB", "LZCS", "LZCR",
];
const CONTROL: [&str; 32] = [
    "RT11RT12", "RT13RT21", "RT22RT23", "RT31RT32", "RT33", "TRX", "TRY", "TRZ", "L11L12",
    "L13L21", "L22L23", "L31L32", "L33", "RBK", "GBK", "BBK", "LR1LR2", "LR3LG1", "LG2LG3",
    "LB1LB2", "LB3", "RFC", "GFC", "BFC", "OFX", "OFY", "H", "DQA", "DQB", "ZSF3", "ZSF4", "FLAG",
];

const fn control(index: u8) -> u8 {
    32 + index
}

fn register(name: &str) -> Option<u8> {
    DATA.iter()
        .position(|known| *known == name)
        .or_else(|| CONTROL.iter().position(|known| *known == name).map(|i| i + 32))
        .map(|index| index as u8)
}

// -- commands ------------------------------------------------------------------

/// psx-spx's command names (the `gte_<name>` userops of `gte.sinc`).
const COMMANDS: [&str; 22] = [
    "rtps", "nclip", "op", "dpcs", "intpl", "mvmva", "ncds", "cdp", "ncdt", "nccs", "cc", "ncs",
    "nct", "sqr", "dcpl", "dpct", "avsz3", "avsz4", "rtpt", "gpf", "gpl", "ncct",
];
/// The commands that take no `sf`/`lm`.
const NO_FLAGS: [&str; 3] = ["nclip", "avsz3", "avsz4"];

// -- load and store macros -------------------------------------------------------

/// One macro over a run of consecutive register accesses. Each slot is one
/// argument: the registers (index, byte offset from the argument) that are
/// loaded from, or stored to, one pointer.
struct Pattern {
    name: &'static str,
    store: bool,
    slots: &'static [&'static [(u8, i64)]],
}

const fn load(name: &'static str, slots: &'static [&'static [(u8, i64)]]) -> Pattern {
    Pattern {
        name,
        store: false,
        slots,
    }
}
const fn store(name: &'static str, slots: &'static [&'static [(u8, i64)]]) -> Pattern {
    Pattern {
        name,
        store: true,
        slots,
    }
}

/// Longest first, so a run matches its widest macro.
static PATTERNS: &[Pattern] = &[
    // Three vertices: VXYn/VZn from three SVECTOR-shaped pointers.
    load(
        "gte_ldv3",
        &[&[(0, 0), (1, 4)], &[(2, 0), (3, 4)], &[(4, 0), (5, 4)]],
    ),
    // The five matrix words (RT11RT12 ... RT33), light matrix, colour matrix.
    load(
        "gte_SetRotMatrix",
        &[&[(control(0), 0), (control(1), 4), (control(2), 8), (control(3), 12), (control(4), 16)]],
    ),
    load(
        "gte_SetLightMatrix",
        &[&[(control(8), 0), (control(9), 4), (control(10), 8), (control(11), 12), (control(12), 16)]],
    ),
    load(
        "gte_SetColorMatrix",
        &[&[(control(16), 0), (control(17), 4), (control(18), 8), (control(19), 12), (control(20), 16)]],
    ),
    // The four screen Z values.
    load("gte_ldsz4", &[&[(16, 0)], &[(17, 0)], &[(18, 0)], &[(19, 0)]]),
    load("gte_ldsxy3", &[&[(12, 0)], &[(13, 0)], &[(14, 0)]]),
    load("gte_ldsz3", &[&[(17, 0)], &[(18, 0)], &[(19, 0)]]),
    load("gte_ldrgb3", &[&[(20, 0)], &[(21, 0)], &[(22, 0)]]),
    // The translation vector sits after the 3x3 short matrix: p+20.
    load(
        "gte_SetTransMatrix",
        &[&[(control(5), 20), (control(6), 24), (control(7), 28)]],
    ),
    store("gte_stsxy3", &[&[(12, 0)], &[(13, 0)], &[(14, 0)]]),
    store("gte_strgb3", &[&[(20, 0)], &[(21, 0)], &[(22, 0)]]),
    // IR1-3 and MAC1-3 as a three-word vector (limited, then unlimited).
    store("gte_stlvl", &[&[(9, 0), (10, 4), (11, 8)]]),
    store("gte_stlvnl", &[&[(25, 0), (26, 4), (27, 8)]]),
    load("gte_ldv0", &[&[(0, 0), (1, 4)]]),
    load("gte_ldv1", &[&[(2, 0), (3, 4)]]),
    load("gte_ldv2", &[&[(4, 0), (5, 4)]]),
];

/// The one-register macro of a data register: the register's own name after
/// `ld`/`st`, with the names the SDK convention gives these.
fn single(register: u8, store: bool) -> Option<String> {
    let name = DATA.get(usize::from(register))?;
    Some(match (register, store) {
        (6, false) => "gte_ldrgb".to_string(),
        (8, false) => "gte_lddp".to_string(),
        (14, true) => "gte_stsxy".to_string(),
        (19, true) => "gte_stsz".to_string(),
        (7, true) => "gte_stotz".to_string(),
        (24, true) => "gte_stopz".to_string(),
        (8, true) => "gte_stdp".to_string(),
        (22, true) => "gte_strgb".to_string(),
        _ => format!("gte_{}{}", if store { "st" } else { "ld" }, name.to_lowercase()),
    })
}

// -- reading a statement -------------------------------------------------------

/// A statement that moves one GTE register to or from memory.
struct Access {
    register: u8,
    store: bool,
    /// The address expression, split into a base and a constant byte offset.
    base: Expr,
    offset: i64,
    /// The tokens of the address operand as PrintC printed them, ready to be
    /// an argument (`param_1`, `&param_1[1]`), when they have such a form.
    address: Option<Vec<Event>>,
    /// A variable event for the base, when it is a named variable.
    base_name: Option<Event>,
}

enum Item {
    Access(Access),
    Command {
        name: &'static str,
        flags: Vec<u64>,
        /// The `op` link PrintC put on the command's name token.
        link: Option<u64>,
    },
    Other,
}

fn opens(event: &Event) -> Option<u64> {
    Some(match event {
        Event::BeginDocument(id)
        | Event::BeginFunction(id)
        | Event::BeginBlock(id, _)
        | Event::BeginReturnType(id, _)
        | Event::BeginVarDecl(id, _)
        | Event::BeginStatement(id, _)
        | Event::BeginFuncProto(id)
        | Event::OpenParen(id, _)
        | Event::OpenGroup(id)
        | Event::StartIndent(id)
        | Event::StartComment(id) => *id,
        _ => return None,
    })
}

fn closes(event: &Event) -> Option<u64> {
    Some(match event {
        Event::EndDocument(id)
        | Event::EndFunction(id)
        | Event::EndBlock(id)
        | Event::EndReturnType(id)
        | Event::EndVarDecl(id)
        | Event::EndStatement(id)
        | Event::EndFuncProto(id)
        | Event::CloseParen(id, _)
        | Event::CloseGroup(id)
        | Event::StopIndent(id)
        | Event::StopComment(id) => *id,
        _ => return None,
    })
}

fn set_id(event: &mut Event, new: u64) {
    match event {
        Event::BeginDocument(id)
        | Event::BeginFunction(id)
        | Event::BeginBlock(id, _)
        | Event::BeginReturnType(id, _)
        | Event::BeginVarDecl(id, _)
        | Event::BeginStatement(id, _)
        | Event::BeginFuncProto(id)
        | Event::OpenParen(id, _)
        | Event::OpenGroup(id)
        | Event::StartIndent(id)
        | Event::StartComment(id)
        | Event::EndDocument(id)
        | Event::EndFunction(id)
        | Event::EndBlock(id)
        | Event::EndReturnType(id)
        | Event::EndVarDecl(id)
        | Event::EndStatement(id)
        | Event::EndFuncProto(id)
        | Event::CloseParen(id, _)
        | Event::CloseGroup(id)
        | Event::StopIndent(id)
        | Event::StopComment(id) => *id = new,
        _ => {}
    }
}

/// Spacing and grouping only: no visible token.
fn layout(event: &Event) -> bool {
    matches!(
        event,
        Event::OpenGroup(_)
            | Event::CloseGroup(_)
            | Event::Spaces(..)
            | Event::StartIndent(_)
            | Event::StopIndent(_)
            | Event::TagLine
            | Event::TagLineIndent(_)
    )
}

/// The events of `slice` without any opener or closer whose partner is
/// outside it, and without leading or trailing spaces.
fn balanced(slice: &[Event]) -> Vec<Event> {
    let opened: HashSet<u64> = slice.iter().filter_map(opens).collect();
    let closed: HashSet<u64> = slice.iter().filter_map(closes).collect();
    let mut kept: Vec<Event> = slice
        .iter()
        .filter(|event| match (opens(event), closes(event)) {
            (Some(id), _) => closed.contains(&id),
            (_, Some(id)) => opened.contains(&id),
            _ => true,
        })
        .cloned()
        .collect();
    while matches!(kept.last(), Some(Event::Spaces(..))) {
        kept.pop();
    }
    let lead = kept
        .iter()
        .take_while(|event| matches!(event, Event::Spaces(..)))
        .count();
    kept.drain(..lead);
    kept
}

/// Index of the first visible event.
fn first_visible(events: &[Event]) -> Option<usize> {
    events.iter().position(|event| !layout(event))
}

/// The index of the `=` of an assignment statement (outside any bracket).
fn assignment(events: &[Event]) -> Option<usize> {
    let mut depth = 0i32;
    for (index, event) in events.iter().enumerate() {
        match event {
            Event::OpenParen(..) => depth += 1,
            Event::CloseParen(..) => depth -= 1,
            Event::Op { name, .. } if depth == 0 && name == "=" => return Some(index),
            _ => {}
        }
    }
    None
}

/// The balanced events from `start` to the closer of `id`.
fn matching_close(events: &[Event], start: usize) -> Option<usize> {
    let id = opens(&events[start])?;
    (start + 1..events.len()).find(|&index| closes(&events[index]) == Some(id))
}

/// `(type) rest` casts at the front of an operand, removed. A cast is a
/// parenthesis around nothing but a type and the `*`s of a pointer type.
fn strip_casts(mut events: Vec<Event>) -> Vec<Event> {
    loop {
        let Some(front) = first_visible(&events) else {
            return events;
        };
        if !matches!(&events[front], Event::OpenParen(_, paren) if paren == "(") {
            return events;
        }
        let Some(back) = matching_close(&events, front) else {
            return events;
        };
        let inside: Vec<&Event> = events[front + 1..back]
            .iter()
            .filter(|event| !layout(event))
            .collect();
        let is_type = inside.iter().any(|event| matches!(event, Event::Type { .. }))
            && inside.iter().all(|event| {
                matches!(event, Event::Type { .. })
                    || matches!(event, Event::Op { name, .. } if name == "*")
            });
        if !is_type {
            return events;
        }
        events.drain(front..=back);
        events = balanced(&events);
    }
}

/// Whether the operand is a variable followed only by `[..]`, `->field` and
/// `.field` suffixes: something `&` applies to without parentheses.
fn postfix(events: &[Event]) -> bool {
    let mut index = 0;
    let mut first = true;
    while index < events.len() {
        match &events[index] {
            event if layout(event) => {}
            Event::Variable {
                name, highlight, ..
            } if first => {
                if *highlight == CONST_COLOR || name.contains('.') {
                    return false;
                }
                first = false;
            }
            Event::OpenParen(_, paren) if !first && paren == "[" => match matching_close(events, index)
            {
                Some(close) => index = close,
                None => return false,
            },
            Event::Op { name, .. } if !first && (name == "->" || name == ".") => {
                // The field that follows.
                loop {
                    index += 1;
                    match events.get(index) {
                        Some(event) if layout(event) => {}
                        Some(Event::Field { .. } | Event::BitField { .. }) => break,
                        _ => return false,
                    }
                }
            }
            _ => return false,
        }
        index += 1;
    }
    !first
}

/// A trailing `& 0xffff` (the zero-extending registers) removed.
fn strip_mask(events: &mut Vec<Event>) {
    let mut depth = 0i32;
    let mut at = None;
    for (index, event) in events.iter().enumerate() {
        match event {
            Event::OpenParen(..) => depth += 1,
            Event::CloseParen(..) => depth -= 1,
            Event::Op { name, .. } if depth == 0 && name == "&" => at = Some(index),
            _ => {}
        }
    }
    // Only a binary `&` (something visible before it) whose right operand is
    // one constant.
    if let Some(at) = at {
        let before = events[..at].iter().any(|event| !layout(event));
        let mask: Vec<&Event> = events[at + 1..].iter().filter(|event| !layout(event)).collect();
        if before
            && matches!(mask.as_slice(), [Event::Variable { highlight, .. }] if *highlight == CONST_COLOR)
        {
            events.truncate(at);
            *events = balanced(events);
        }
    }
}

/// The tokens that make `operand` (the memory operand of a load or store, as
/// PrintC printed it) an argument holding its address.
fn address_of(operand: &[Event], op: u64) -> Option<Vec<Event>> {
    let mut operand = strip_casts(balanced(operand));
    strip_mask(&mut operand);
    let front = first_visible(&operand)?;
    if matches!(&operand[front], Event::Op { name, .. } if name == "*") {
        // `*p`, `*(T *)(p + 4)`: the pointer itself.
        let pointer = balanced(&operand[front + 1..]);
        return first_visible(&pointer).map(|_| pointer);
    }
    if !postfix(&operand) {
        return None;
    }
    let mut tokens = vec![Event::Op {
        name: "&".into(),
        highlight: NO_COLOR,
        op: Some(op),
    }];
    tokens.extend(operand);
    Some(tokens)
}

fn signed_constant(expr: &Expr) -> Option<i64> {
    match expr {
        Expr::Const { size, value } => {
            let bits = (*size).clamp(1, 8) * 8;
            let shift = 64 - bits;
            Some(((*value << shift) as i64) >> shift)
        }
        _ => None,
    }
}

/// `address` as a base expression plus a constant byte offset.
fn split(address: &Expr) -> (Expr, i64) {
    if let Expr::Op { code, args } = address {
        match (*code, args.as_slice()) {
            (CAST, [inner]) => return split(inner),
            (INT_ADD, [left, right]) => {
                if let Some(constant) = signed_constant(right) {
                    let (base, offset) = split(left);
                    return (base, offset.wrapping_add(constant));
                }
                if let Some(constant) = signed_constant(left) {
                    let (base, offset) = split(right);
                    return (base, offset.wrapping_add(constant));
                }
            }
            (INT_SUB, [left, right]) => {
                if let Some(constant) = signed_constant(right) {
                    let (base, offset) = split(left);
                    return (base, offset.wrapping_sub(constant));
                }
            }
            (PTRSUB, [left, right]) => {
                if let Some(constant) = signed_constant(right) {
                    let (base, offset) = split(left);
                    return (base, offset.wrapping_add(constant));
                }
            }
            (PTRADD, [left, index, element]) => {
                if let (Some(index), Some(element)) = (signed_constant(index), signed_constant(element)) {
                    let (base, offset) = split(left);
                    return (base, offset.wrapping_add(index.wrapping_mul(element)));
                }
            }
            _ => {}
        }
    }
    if let Expr::Const { size, value } = address {
        return (
            Expr::Const {
                size: *size,
                value: 0,
            },
            signed_constant(address).unwrap_or(*value as i64),
        );
    }
    (address.clone(), 0)
}

/// What a register write reads memory through, or a memory write goes to.
enum Operand<'a> {
    /// `*address`.
    Pointer(&'a Expr),
    /// A variable that lives in memory (`DAT_80123450`, `uRam80123450`).
    Global(&'a Expr),
}

/// The memory operand under a (possibly narrowing, extending or masking)
/// read of memory.
fn memory_operand(expr: &Expr) -> Option<Operand<'_>> {
    match expr {
        Expr::Op { code: LOAD, args } => args.get(1).map(Operand::Pointer),
        Expr::Op {
            code: SUBPIECE | CAST | INT_SEXT | INT_ZEXT,
            args,
        } => memory_operand(args.first()?),
        // The 16-bit registers read zero-extended: `x & 0xffff`.
        Expr::Op {
            code: INT_AND,
            args,
        } => match args.as_slice() {
            [inner, Expr::Const { .. }] => memory_operand(inner),
            _ => None,
        },
        Expr::Var { storage, .. } if storage.class == 2 => Some(Operand::Global(expr)),
        _ => None,
    }
}

/// The memory operand a register-writing statement reads.
fn read_operand(effect: &Effect) -> Option<Operand<'_>> {
    match (effect.code, effect.args.as_slice()) {
        (LOAD, [_, address]) => Some(Operand::Pointer(address)),
        (INT_AND, [inner, Expr::Const { .. }]) => memory_operand(inner),
        (COPY | INT_SEXT | INT_ZEXT | SUBPIECE | CAST, [inner]) => memory_operand(inner),
        _ => None,
    }
}

/// The address a variable in memory is named for: Ghidra names an unlabelled
/// global `DAT_<address>` or `<type letter>Ram<address>`.
fn global_address(name: &str) -> Option<i64> {
    let name = name.trim_start_matches('_');
    let digits = name.get(name.len().checked_sub(8)?..)?;
    let prefix = &name[..name.len() - 8];
    if prefix != "DAT_" && !(prefix.ends_with("Ram") && prefix.len() <= 5) {
        return None;
    }
    if !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(i64::from(u32::from_str_radix(digits, 16).ok()? as i32))
}

/// The base and offset of a memory operand: a pointer's address expression
/// split, or a global's own address.
fn locate(operand: &Operand<'_>, events: &[Event]) -> (Expr, i64) {
    match operand {
        Operand::Pointer(address) => split(address),
        Operand::Global(var) => {
            let named = match var {
                Expr::Var { ssa, .. } => events.iter().find_map(|event| match event {
                    Event::Variable {
                        name,
                        varnode: Some(id),
                        ..
                    } if id == ssa => Some(name.as_str()),
                    _ => None,
                }),
                _ => None,
            };
            match named.and_then(global_address) {
                Some(address) => (
                    Expr::Const {
                        size: 4,
                        value: 0,
                    },
                    address,
                ),
                None => ((*var).clone(), 0),
            }
        }
    }
}

fn variable_named(events: &[Event]) -> Option<&str> {
    events.iter().find_map(|event| match event {
        Event::Variable { name, .. } => Some(name.as_str()),
        _ => None,
    })
}

fn classify(statement: &Statement) -> Item {
    let events = &statement.expression.normal.0;
    let effect = &statement.effect;
    if statement.is_branch {
        return Item::Other;
    }
    if effect.code == CALLOTHER {
        return command(statement).unwrap_or(Item::Other);
    }
    let Some(split_at) = assignment(events) else {
        return Item::Other;
    };
    let (left, right) = (&events[..split_at], &events[split_at + 1..]);
    let op = statement.op;
    let left_register = variable_named(left).and_then(register);
    if let (Some(register), Some(Expr::Var { .. })) = (left_register, &effect.out) {
        // `GTE_REG = *address;`, `GTE_REG = global;`
        let Some(operand) = read_operand(effect) else {
            return Item::Other;
        };
        let (base, offset) = locate(&operand, right);
        return Item::Access(Access {
            register,
            store: false,
            base_name: named_base(&base, right),
            base,
            offset,
            address: address_of(right, op),
        });
    }
    // `*address = GTE_REG;`, `global = GTE_REG;`
    let Some(register) = variable_named(right)
        .and_then(register)
        .filter(|register| *register < 32)
    else {
        return Item::Other;
    };
    let operand = match (effect.code, effect.args.as_slice(), &effect.out) {
        (STORE, [_, address, Expr::Var { .. }], _) => Operand::Pointer(address),
        (COPY, [Expr::Var { .. }], Some(out @ Expr::Var { storage, .. })) if storage.class == 2 => {
            Operand::Global(out)
        }
        _ => return Item::Other,
    };
    let (base, offset) = locate(&operand, left);
    Item::Access(Access {
        register,
        store: true,
        base_name: named_base(&base, left),
        base,
        offset,
        address: address_of(left, op),
    })
}

/// The variable event naming `base`, when `base` is a variable.
fn named_base(base: &Expr, operand: &[Event]) -> Option<Event> {
    let Expr::Var { ssa, .. } = base else {
        return None;
    };
    operand
        .iter()
        .find(|event| matches!(event, Event::Variable { varnode: Some(id), .. } if id == ssa))
        .cloned()
}

/// A `gte_<command>(...)` userop statement with constant flags.
fn command(statement: &Statement) -> Option<Item> {
    let events = &statement.expression.normal.0;
    let (name, link) = events.iter().find_map(|event| match event {
        Event::Op { name, op, .. } | Event::FuncName { name, op, .. } => {
            let command = name.strip_prefix("gte_")?;
            COMMANDS
                .iter()
                .find(|known| **known == command)
                .map(|known| (*known, *op))
        }
        _ => None,
    })?;
    let flags = statement
        .effect
        .args
        .iter()
        .skip(1)
        .map(|arg| match arg {
            Expr::Const { value, .. } => Some(*value),
            _ => None,
        })
        .collect::<Option<Vec<u64>>>()?;
    let wanted = if NO_FLAGS.contains(&name) {
        0
    } else if name == "mvmva" {
        5
    } else {
        2
    };
    if flags.len() != wanted {
        return None;
    }
    Some(Item::Command { name, flags, link })
}

// -- building a call ---------------------------------------------------------------

/// Builds a fragment, numbering the ids of the events it opens from 1.
#[derive(Default)]
struct Builder {
    events: Vec<Event>,
    next: u64,
    map: HashMap<u64, u64>,
}

impl Builder {
    fn fresh(&mut self) -> u64 {
        self.next += 1;
        self.next
    }

    /// Copies `source`, renumbering the ids it opens and the closers that
    /// follow them.
    fn copy(&mut self, source: &[Event]) {
        for event in source {
            let mut event = event.clone();
            if let Some(old) = opens(&event) {
                let new = self.fresh();
                self.map.insert(old, new);
                set_id(&mut event, new);
            } else if let Some(old) = closes(&event) {
                let Some(new) = self.map.get(&old) else {
                    continue;
                };
                set_id(&mut event, *new);
            }
            self.events.push(event);
        }
    }
}

/// `name(arg, ...)` the way PrintC prints a userop call.
fn call(name: &str, op: u64, args: &[Vec<Event>]) -> Fragment {
    let mut builder = Builder::default();
    let group = builder.fresh();
    builder.events.push(Event::OpenGroup(group));
    builder.events.push(Event::Op {
        name: name.to_string(),
        highlight: FUNCNAME_COLOR,
        op: Some(op),
    });
    builder.events.push(Event::Spaces(0, CALL_BUMP));
    let paren = builder.fresh();
    builder.events.push(Event::OpenParen(paren, "(".into()));
    builder.events.push(Event::Spaces(0, CALL_BUMP));
    // The arguments are one group, so a long call breaks as PrintC's would.
    let list = (!args.is_empty()).then(|| builder.fresh());
    if let Some(list) = list {
        builder.events.push(Event::OpenGroup(list));
    }
    for (index, arg) in args.iter().enumerate() {
        if index > 0 {
            builder.events.push(Event::Spaces(0, 0));
            builder.events.push(Event::Op {
                name: ",".into(),
                highlight: NO_COLOR,
                op: Some(op),
            });
            builder.events.push(Event::Spaces(0, 0));
        }
        builder.copy(arg);
    }
    if let Some(list) = list {
        builder.events.push(Event::CloseGroup(list));
    }
    builder.events.push(Event::CloseParen(paren, ")".into()));
    builder.events.push(Event::CloseGroup(group));
    Fragment(builder.events)
}

fn constant(value: u64, op: u64) -> Vec<Event> {
    vec![Event::Variable {
        name: value.to_string(),
        highlight: CONST_COLOR,
        varnode: None,
        op: Some(op),
    }]
}

/// A statement printing `fragment`, standing for `first` and what followed it.
fn replacement(first: &Statement, fragment: Fragment) -> Statement {
    let mut statement = first.clone();
    statement.expression = Expression {
        normal: fragment,
        comma: None,
        source: Source::Rust,
    };
    statement.effect = Effect {
        code: CALLOTHER,
        calls: true,
        stores: true,
        out: None,
        flip: false,
        args: Vec::new(),
    };
    statement
}

// -- matching ---------------------------------------------------------------------------

/// The arguments of `pattern` if `items` starts with its run.
fn run(pattern: &Pattern, items: &[Item]) -> Option<Vec<Vec<Event>>> {
    let total: usize = pattern.slots.iter().map(|slot| slot.len()).sum();
    if items.len() < total {
        return None;
    }
    let mut args = Vec::new();
    let mut at = 0;
    for slot in pattern.slots {
        let mut anchor: Option<&Access> = None;
        for &(register, offset) in *slot {
            let Item::Access(access) = &items[at] else {
                return None;
            };
            if access.register != register || access.store != pattern.store {
                return None;
            }
            match anchor {
                None => anchor = Some(access),
                Some(first) => {
                    let (_, first_offset) = slot[0];
                    if access.base != first.base
                        || access.offset != first.offset + (offset - first_offset)
                    {
                        return None;
                    }
                }
            }
            at += 1;
        }
        let first = anchor?;
        let (_, first_offset) = slot[0];
        args.push(if first_offset == 0 {
            first.address.clone()?
        } else {
            // The argument is the structure the offset is inside of.
            vec![first.base_name.clone()?]
        });
    }
    Some(args)
}

fn lift_block(basic: &mut Basic, stats: &mut GteStats) {
    if basic.holds_loop_op {
        return;
    }
    let items: Vec<Item> = basic.statements.iter().map(classify).collect();
    if items.iter().all(|item| matches!(item, Item::Other)) {
        return;
    }
    let mut out: Vec<Statement> = Vec::with_capacity(basic.statements.len());
    let mut index = 0;
    while index < items.len() {
        let statement = &basic.statements[index];
        let op = statement.op;
        match &items[index] {
            Item::Other => {
                out.push(statement.clone());
                index += 1;
            }
            Item::Command { name, flags, link } => {
                let mut args = Vec::new();
                let default = if *name == "mvmva" {
                    false
                } else {
                    flags.as_slice() == [1, 0] || NO_FLAGS.contains(name)
                };
                if !default {
                    args.extend(flags.iter().map(|flag| constant(*flag, op)));
                }
                let printed = format!("gte_{}", name.to_uppercase());
                let mut fragment = call(&printed, op, &args);
                // The command's own token keeps the link PrintC gave it.
                if let Some(Event::Op { op: token, .. }) = fragment.0.get_mut(1) {
                    *token = *link;
                }
                *stats.macros.entry(printed).or_default() += 1;
                out.push(replacement(statement, fragment));
                index += 1;
            }
            Item::Access(_) => {
                let matched = PATTERNS
                    .iter()
                    .find_map(|pattern| run(pattern, &items[index..]).map(|args| (pattern, args)));
                if let Some((pattern, args)) = matched {
                    let used: usize = pattern.slots.iter().map(|slot| slot.len()).sum();
                    *stats.macros.entry(pattern.name.to_string()).or_default() += 1;
                    stats.accesses_folded += used as u64;
                    out.push(replacement(statement, call(pattern.name, op, &args)));
                    index += used;
                    continue;
                }
                let Item::Access(access) = &items[index] else {
                    unreachable!()
                };
                match (single(access.register, access.store), &access.address) {
                    (Some(name), Some(address)) => {
                        *stats.macros.entry(name.clone()).or_default() += 1;
                        stats.accesses_folded += 1;
                        out.push(replacement(
                            statement,
                            call(&name, op, std::slice::from_ref(address)),
                        ));
                    }
                    _ => {
                        stats.accesses_left += 1;
                        out.push(statement.clone());
                    }
                }
                index += 1;
            }
        }
    }
    basic.statements = out;
}

fn lift_node(node: &mut Node, stats: &mut GteStats) {
    if let Detail::Basic(basic) = &mut node.detail {
        lift_block(basic, stats);
    }
    for child in &mut node.children {
        lift_node(child, stats);
    }
    if let Detail::Switch { cases } = &mut node.detail {
        for case in cases {
            if let CaseBody::Block(block) = &mut case.body {
                lift_node(block, stats);
            }
        }
    }
}

/// Folds the function's GTE statements into macro calls.
pub fn lift(ir: &mut PrinterIr) -> GteStats {
    let mut stats = GteStats::default();
    for node in &mut ir.body {
        lift_node(node, &mut stats);
    }
    stats
}

#[cfg(test)]
mod tests {
    //! Statements shaped as `ghidra_opt` exports them for the PSX language
    //! (fragments recorded from `VXY0 = *param_1;`, `gte_rtps(1,0);` and
    //! `*param_2 = SXY2;`).

    use super::*;
    use crate::printc::ir::Storage;

    const REGISTER: Storage = Storage {
        class: 0,
        aliased: true,
    };
    const LOCAL: Storage = Storage {
        class: 0,
        aliased: false,
    };

    fn var(name: &str, highlight: u8, varnode: u64, op: u64) -> Event {
        Event::Variable {
            name: name.into(),
            highlight,
            varnode: Some(varnode),
            op: Some(op),
        }
    }

    fn op_token(name: &str, op: u64) -> Event {
        Event::Op {
            name: name.into(),
            highlight: NO_COLOR,
            op: Some(op),
        }
    }

    /// `(name)` as PrintC prints a cast, with `id` as its paren id.
    fn cast(name: &str, id: u64) -> Vec<Event> {
        vec![
            Event::OpenParen(id, "(".into()),
            Event::OpenGroup(id + 100),
            Event::Type {
                name: name.into(),
                highlight: 2,
                id: 1,
            },
            Event::Spaces(0, 0),
            Event::CloseGroup(id + 100),
            Event::CloseParen(id, ")".into()),
            Event::Spaces(0, 0),
        ]
    }

    fn fragment(events: Vec<Event>) -> Fragment {
        Fragment(events)
    }

    fn statement(op: u64, events: Vec<Event>, effect: Effect) -> Statement {
        Statement {
            op,
            is_branch: false,
            comment_bound: 0,
            expression: Expression {
                normal: fragment(events),
                comma: None,
                source: Source::Fragments,
            },
            effect,
        }
    }

    fn constant(value: u64) -> Expr {
        Expr::Const { size: 4, value }
    }

    fn pointer(ssa: u64) -> Expr {
        Expr::Var {
            size: 4,
            ssa,
            high: 2,
            storage: LOCAL,
        }
    }

    fn register_var(ssa: u64) -> Expr {
        Expr::Var {
            size: 4,
            ssa,
            high: 1,
            storage: REGISTER,
        }
    }

    /// `REG = *param_1;` (`element` 0) or `REG = (int)(short)param_1[element];`.
    fn load_statement(op: u64, register_name: &str, element: u64) -> Statement {
        let mut events = vec![
            Event::OpenGroup(1),
            var(register_name, 7, 100 + op, op),
            Event::Spaces(1, 5),
            op_token("=", op),
            Event::Spaces(1, 5),
            Event::OpenGroup(2),
        ];
        let address = if element == 0 {
            events.push(op_token("*", op));
            events.push(Event::Spaces(0, 0));
            events.push(var("param_1", 6, 75, op));
            pointer(75)
        } else {
            events.extend(cast("int", 3));
            events.extend(cast("short", 4));
            events.push(var("param_1", 6, 75, op));
            events.push(Event::Spaces(0, 0));
            events.push(Event::OpenParen(5, "[".into()));
            events.push(Event::Spaces(0, 0));
            events.push(var(&element.to_string(), CONST_COLOR, 200 + op, op));
            events.push(Event::CloseParen(5, "]".into()));
            Expr::Op {
                code: PTRADD,
                args: vec![pointer(75), constant(element), constant(4)],
            }
        };
        events.push(Event::CloseGroup(2));
        events.push(Event::CloseGroup(1));
        let loaded = Expr::Op {
            code: LOAD,
            args: vec![constant(0x2800), address],
        };
        let (code, args) = if element == 0 {
            (LOAD, vec![constant(0x2800), pointer(75)])
        } else {
            (
                INT_SEXT,
                vec![Expr::Op {
                    code: SUBPIECE,
                    args: vec![loaded, constant(0)],
                }],
            )
        };
        statement(
            op,
            events,
            Effect {
                code,
                out: Some(register_var(100 + op)),
                args,
                ..Effect::default()
            },
        )
    }

    /// `*param_2 = SXY2;` or `param_2[n] = SXY2;`
    fn store_statement(op: u64, register_name: &str, pointer_name: &str, ssa: u64) -> Statement {
        let events = vec![
            Event::OpenGroup(1),
            Event::OpenGroup(2),
            op_token("*", op),
            Event::Spaces(0, 0),
            var(pointer_name, 6, ssa, op),
            Event::CloseGroup(2),
            Event::Spaces(1, 5),
            op_token("=", op),
            Event::Spaces(1, 5),
            var(register_name, 7, 300 + op, op),
            Event::CloseGroup(1),
        ];
        statement(
            op,
            events,
            Effect {
                code: STORE,
                stores: true,
                args: vec![constant(0x2800), pointer(ssa), register_var(300 + op)],
                ..Effect::default()
            },
        )
    }

    /// `gte_<name>(a,b);`
    fn command_statement(op: u64, name: &str, flags: &[u64]) -> Statement {
        let mut events = vec![
            Event::OpenGroup(1),
            Event::Op {
                name: name.into(),
                highlight: FUNCNAME_COLOR,
                op: Some(op),
            },
            Event::Spaces(0, CALL_BUMP),
            Event::OpenParen(2, "(".into()),
            Event::Spaces(0, CALL_BUMP),
        ];
        if !flags.is_empty() {
            events.push(Event::OpenGroup(3));
            for (index, flag) in flags.iter().enumerate() {
                if index > 0 {
                    events.push(Event::Spaces(0, 0));
                    events.push(op_token(",", op));
                    events.push(Event::Spaces(0, 0));
                }
                events.push(var(&flag.to_string(), CONST_COLOR, 400 + op, op));
            }
            events.push(Event::CloseGroup(3));
        }
        events.push(Event::CloseParen(2, ")".into()));
        events.push(Event::CloseGroup(1));
        let mut args = vec![constant(0x10)];
        args.extend(flags.iter().map(|flag| constant(*flag)));
        statement(
            op,
            events,
            Effect {
                code: CALLOTHER,
                calls: true,
                args,
                ..Effect::default()
            },
        )
    }

    /// The tokens of a fragment as one string, without layout.
    fn text(statement: &Statement) -> String {
        statement
            .expression
            .normal
            .0
            .iter()
            .map(|event| match event {
                Event::Variable { name, .. }
                | Event::Op { name, .. }
                | Event::FuncName { name, .. }
                | Event::Type { name, .. }
                | Event::Field { name, .. } => name.clone(),
                Event::Print { text, .. } => text.clone(),
                Event::OpenParen(_, paren) | Event::CloseParen(_, paren) => paren.clone(),
                _ => String::new(),
            })
            .collect()
    }

    fn basic(statements: Vec<Statement>) -> Basic {
        Basic {
            comments: Vec::new(),
            statements,
            branch: None,
            successors: Vec::new(),
            negated: None,
            holds_loop_op: false,
            threaded: Vec::new(),
        }
    }

    fn lifted(statements: Vec<Statement>) -> (Vec<String>, GteStats) {
        let mut block = basic(statements);
        let mut stats = GteStats::default();
        lift_block(&mut block, &mut stats);
        (block.statements.iter().map(text).collect(), stats)
    }

    /// Fragment-local ids open in order from 1 and every opener closes.
    fn well_formed(statement: &Statement) {
        let mut open = Vec::new();
        let mut next = 1;
        for event in &statement.expression.normal.0 {
            if let Some(id) = opens(event) {
                assert_eq!(id, next, "{event:?}");
                next += 1;
                open.push(id);
            } else if let Some(id) = closes(event) {
                assert_eq!(open.pop(), Some(id), "{event:?}");
            }
        }
        assert!(open.is_empty());
        assert_eq!(statement.expression.source, Source::Rust);
    }

    #[test]
    fn a_vertex_pair_a_command_and_a_store_become_three_calls() {
        let statements = vec![
            load_statement(3, "VXY0", 0),
            load_statement(8, "VZ0", 1),
            command_statement(9, "gte_rtps", &[1, 0]),
            store_statement(13, "SXY2", "param_2", 76),
        ];
        let mut block = basic(statements);
        let mut stats = GteStats::default();
        lift_block(&mut block, &mut stats);
        let printed: Vec<String> = block.statements.iter().map(text).collect();
        assert_eq!(printed, ["gte_ldv0(param_1)", "gte_RTPS()", "gte_stsxy(param_2)"]);
        block.statements.iter().for_each(well_formed);
        assert_eq!(stats.total(), 3);
        assert_eq!(stats.accesses_folded, 3);
        assert_eq!(stats.macros["gte_ldv0"], 1);
        // The first statement's op links the call; the effect says it calls.
        assert_eq!(block.statements[0].op, 3);
        assert!(block.statements[0].effect.calls && block.statements[0].effect.stores);
    }

    #[test]
    fn three_vertices_fold_to_one_call_with_their_addresses() {
        let statements = vec![
            load_statement(1, "VXY0", 0),
            load_statement(2, "VZ0", 1),
            load_statement(3, "VXY1", 2),
            load_statement(4, "VZ1", 3),
            load_statement(5, "VXY2", 4),
            load_statement(6, "VZ2", 5),
        ];
        let (printed, stats) = lifted(statements);
        assert_eq!(
            printed,
            ["gte_ldv3(param_1,&param_1[2],&param_1[4])"]
        );
        assert_eq!(stats.accesses_folded, 6);
    }

    #[test]
    fn a_pair_whose_halves_are_apart_prints_one_call_per_register() {
        // VXY0 from param_1[0], VZ0 from param_1[3]: not the same vertex.
        let statements = vec![load_statement(1, "VXY0", 0), load_statement(2, "VZ0", 3)];
        let (printed, _) = lifted(statements);
        assert_eq!(printed, ["gte_ldvxy0(param_1)", "gte_ldvz0(&param_1[3])"]);
    }

    #[test]
    fn an_unrelated_statement_ends_a_run() {
        let other = statement(
            5,
            vec![Event::Print {
                text: "x = 1".into(),
                highlight: 0,
            }],
            Effect::default(),
        );
        let statements = vec![
            load_statement(1, "VXY0", 0),
            other,
            load_statement(2, "VZ0", 1),
        ];
        let (printed, _) = lifted(statements);
        assert_eq!(printed, ["gte_ldvxy0(param_1)", "x = 1", "gte_ldvz0(&param_1[1])"]);
    }

    #[test]
    fn command_flags_print_unless_they_are_the_default() {
        for (name, flags, expected) in [
            ("gte_rtpt", vec![1, 0], "gte_RTPT()"),
            ("gte_rtpt", vec![0, 1], "gte_RTPT(0,1)"),
            ("gte_ncds", vec![1, 1], "gte_NCDS(1,1)"),
            ("gte_nclip", vec![], "gte_NCLIP()"),
            ("gte_avsz3", vec![], "gte_AVSZ3()"),
            ("gte_mvmva", vec![1, 0, 0, 0, 0], "gte_MVMVA(1,0,0,0,0)"),
        ] {
            let (printed, _) = lifted(vec![command_statement(9, name, &flags)]);
            assert_eq!(printed, [expected]);
        }
    }

    #[test]
    fn a_command_with_unexpected_arguments_is_left_alone() {
        // `gte_rtps(x)`: one argument that is not the two constants.
        let (printed, stats) = lifted(vec![command_statement(9, "gte_rtps", &[1])]);
        assert_eq!(printed, ["gte_rtps(1)"]);
        assert_eq!(stats.total(), 0);
    }

    #[test]
    fn three_stores_make_stsxy3() {
        let statements = vec![
            store_statement(1, "SXY0", "param_2", 76),
            store_statement(2, "SXY1", "param_3", 77),
            store_statement(3, "SXY2", "param_4", 78),
        ];
        let (printed, _) = lifted(statements);
        assert_eq!(printed, ["gte_stsxy3(param_2,param_3,param_4)"]);
    }

    #[test]
    fn a_loop_initializer_block_is_not_touched() {
        let mut block = basic(vec![load_statement(1, "VXY0", 0)]);
        block.holds_loop_op = true;
        let mut stats = GteStats::default();
        lift_block(&mut block, &mut stats);
        assert_eq!(text(&block.statements[0]), "VXY0=*param_1");
        assert_eq!(stats, GteStats::default());
    }

    #[test]
    fn a_statement_that_is_not_a_gte_access_is_kept_verbatim() {
        let mut other = load_statement(1, "VXY0", 0);
        // The same shape, but the written variable is an ordinary one.
        if let Event::Variable { name, .. } = &mut other.expression.normal.0[1] {
            *name = "uVar1".into();
        }
        let (printed, stats) = lifted(vec![other]);
        assert_eq!(printed, ["uVar1=*param_1"]);
        assert_eq!(stats.total(), 0);
    }

    #[test]
    fn global_names_carry_their_address() {
        assert_eq!(global_address("uRam80123450"), Some(0x80123450u32 as i32 as i64));
        assert_eq!(global_address("DAT_80123450"), Some(0x80123450u32 as i32 as i64));
        assert_eq!(global_address("_DAT_80123450"), Some(0x80123450u32 as i32 as i64));
        assert_eq!(global_address("camera_pos"), None);
        assert_eq!(global_address("local_20"), None);
    }
}
