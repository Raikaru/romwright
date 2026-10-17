//! Stage 3 of the decompiler port: who decides which values share a C
//! variable, which print as sub-expressions (`merge.cc`, `ActionMarkExplicit`,
//! `ActionMarkImplied`), the for-loop op moves, and the variable names.
//! docs/merge-port.md has the design; `native/romwright_merge.hh` is the C++
//! side (the mirror writer, the log replay and the stock fallback).
//!
//! The decompiler sends a mirror of the function's p-code after
//! `ActionAssignHigh` (marker 2); [`decide`] runs the actions the stage
//! replaces over it and the answer is the log of every edit and decision,
//! replayed on the real `Funcdata`. A function the port cannot decide is
//! declined and the decompiler runs its own actions.

pub mod actions;
pub mod cover;
pub mod explicit;
pub mod loops;
pub mod names;
pub mod model;
pub mod pieces;

mod sortcxx;
pub mod variant;

#[cfg(test)]
mod tests;

pub use variant::{Variant, set_variants};

use model::{AddrSpec, At, Entry, Func, Result, opc, vf};
use std::cell::RefCell;

thread_local! {
    /// `ROMWRIGHT_RUST_MERGE=verify`: the worker's final state, until the decompiler's own arrives.
    static VERIFY: RefCell<Option<Func>> = const { RefCell::new(None) };
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    On,
    Off,
    Verify,
}

fn mode() -> Mode {
    match std::env::var("ROMWRIGHT_RUST_MERGE").as_deref() {
        Ok("off" | "0" | "native") => Mode::Off,
        Ok("verify") => Mode::Verify,
        _ => Mode::On,
    }
}

pub fn log_line(line: serde_json::Value) {
    if let Some(path) = std::env::var_os("ROMWRIGHT_RUST_MERGE_LOG") {
        use std::io::Write;
        if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(file, "{line}");
        }
    }
}

pub(super) fn put(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = 0x40 | (value & 0x3f) as u8;
        value >>= 6;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn declined(address: u64, reason: &str) -> Vec<u8> {
    log_line(serde_json::json!({"merge_declined": reason, "address": address}));
    b"n".to_vec()
}

impl Func {
    /// The functions the port does not model are refused up front.
    fn check_supported(&self, multi_entry: bool, dynamic: bool) -> Result<()> {
        if multi_entry {
            return Err("merge:multi-entry-symbol".into());
        }
        if dynamic {
            return Err("merge:dynamic-symbol".into());
        }
        for vn in &self.vns {
            if vn.flags & (vf::IMPLIED | vf::EXPLICIT) != 0 {
                return Err("merge:already-marked".into());
            }
        }
        for op in &self.ops {
            if op.code == opc::INDIRECT && op.target.is_none() && op.ins.len() > 1 {
                return Err("merge:indirect-target".into());
            }
        }
        Ok(())
    }

    /// Runs the actions the stage replaces, in the pipeline's order.
    pub fn decide(&mut self) -> Result<()> {
        // ActionStructureTransform's for-loop moves (they read op order only).
        if !self.variant.explicit.is_empty() || !self.variant.separate.is_empty() {
            self.resolve_variant();
        }
        self.loop_transform();
        // ActionMergeRequired
        self.merge_addr_tied()?;
        self.group_partials()?;
        self.merge_marker()?;
        // ActionMarkExplicit, ActionMarkImplied
        self.mark_explicit();
        self.mark_implied_action()?;
        // ActionMergeCopy, ActionDominantCopy
        if self.variant.copy {
            self.merge_opcode(opc::COPY)?;
        }
        if self.variant.dominant {
            self.process_copy_trims()?;
        }
        // ActionMarkIndirectOnly
        self.mark_indirect_only();
        // ActionMergeAdjacent, ActionMergeType
        if self.variant.adjacent {
            self.merge_adjacent()?;
        }
        if self.variant.datatype {
            self.merge_by_datatype()?;
        }
        // ActionHideShadow, ActionCopyMarker
        if self.variant.hide_shadow {
            self.hide_shadow_action();
        }
        self.mark_internal_copies();
        // ActionFinalStructure's for-loop tests
        self.loop_finalize();
        if let Some(why) = self.err.borrow().clone() {
            return Err(why);
        }
        Ok(())
    }
}

fn encode_log(f: &Func) -> Vec<u8> {
    let mut out = vec![b'o'];
    for entry in &f.log {
        match entry {
            Entry::NewCopy(spec) => {
                put(&mut out, 1);
                let (kind, id) = match spec {
                    AddrSpec::OpAddr(o) => (0, *o),
                    AddrSpec::BlockStart(b) => (1, *b),
                    AddrSpec::BlockStop(b) => (2, *b),
                };
                put(&mut out, kind);
                put(&mut out, id as u64);
            }
            Entry::NewUnique { size, ty_from } => {
                put(&mut out, 2);
                put(&mut out, u64::from(*size));
                put(&mut out, *ty_from as u64);
            }
            Entry::SetOutput { op, vn } => {
                put(&mut out, 3);
                put(&mut out, *op as u64);
                put(&mut out, *vn as u64);
            }
            Entry::SetInput { op, vn, slot } => {
                put(&mut out, 4);
                put(&mut out, *op as u64);
                put(&mut out, *vn as u64);
                put(&mut out, *slot as u64);
            }
            Entry::Insert { op, at } => {
                put(&mut out, 5);
                put(&mut out, *op as u64);
                let (kind, id) = match at {
                    At::Before(o) => (0, *o),
                    At::After(o) => (1, *o),
                    At::Begin(b) => (2, *b),
                    At::End(b) => (3, *b),
                };
                put(&mut out, kind);
                put(&mut out, id as u64);
            }
            Entry::Uninsert { op } => {
                put(&mut out, 6);
                put(&mut out, *op as u64);
            }
            Entry::Destroy { op } => {
                put(&mut out, 7);
                put(&mut out, *op as u64);
            }
            Entry::TotalReplace { old, new } => {
                put(&mut out, 8);
                put(&mut out, *old as u64);
                put(&mut out, *new as u64);
            }
            Entry::HighRemove { vn } => {
                put(&mut out, 9);
                put(&mut out, *vn as u64);
            }
            Entry::Merge { a, b, speculative } => {
                put(&mut out, 10);
                put(&mut out, *a as u64);
                put(&mut out, *b as u64);
                put(&mut out, u64::from(*speculative));
            }
            Entry::SetExplicit(v) => {
                put(&mut out, 11);
                put(&mut out, *v as u64);
            }
            Entry::ClearImplied(v) => {
                put(&mut out, 12);
                put(&mut out, *v as u64);
            }
            Entry::MarkImplied(v) => {
                put(&mut out, 13);
                put(&mut out, *v as u64);
            }
            Entry::NonPrint(o) => {
                put(&mut out, 14);
                put(&mut out, *o as u64);
            }
            Entry::Print(o) => {
                put(&mut out, 15);
                put(&mut out, *o as u64);
            }
            Entry::SpecialPrint(o) => {
                put(&mut out, 16);
                put(&mut out, *o as u64);
            }
            Entry::IndirectOnly(v) => {
                put(&mut out, 17);
                put(&mut out, *v as u64);
            }
            Entry::GroupWith { a, b, off } => {
                put(&mut out, 18);
                put(&mut out, *a as u64);
                put(&mut out, *b as u64);
                put(&mut out, (*off as i64 as u64) << 1 ^ ((*off as i64 >> 63) as u64));
            }
            Entry::ClearProtoPartial(v) => {
                put(&mut out, 19);
                put(&mut out, *v as u64);
            }
        }
    }
    put(&mut out, 0);
    put(&mut out, f.loops.len() as u64);
    for l in &f.loops {
        put(&mut out, l.head as u64);
        put(&mut out, l.tail as u64);
        put(&mut out, l.init.map_or(0, |o| o as u64 + 1));
        put(&mut out, l.iter.map_or(0, |o| o as u64 + 1));
    }
    out
}

/// The merge query (marker 2): decides the function, or declines.
pub fn answer_merge(payload: &[u8]) -> Vec<u8> {
    let m = mode();
    let query = match super::ir::decode_merge_query(payload) {
        Ok(q) => q,
        Err(reason) => return declined(0, &format!("decode:{reason}")),
    };
    let (mut f, multi_entry, dynamic) = (query.func, query.multi_entry, query.dynamic);
    let address = f.address;
    if m == Mode::Off {
        return declined(address, "off");
    }
    if let Err(reason) = f.check_supported(multi_entry, dynamic) {
        return declined(address, &reason);
    }
    f.variant = variant::for_function(address);
    let started = std::time::Instant::now();
    // A bug in the port must cost the function its worker decision, not the worker.
    let decided = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f.decide()));
    match decided {
        Ok(Ok(())) => {}
        Ok(Err(reason)) => return declined(address, &reason),
        Err(_) => return declined(address, "merge:panic"),
    }
    log_line(serde_json::json!({"merge_ok": {
        "address": address,
        "merges": f.extra.merges,
        "speculative": f.extra.speculative,
        "explicit": f.extra.explicit,
        "implied": f.extra.implied,
        "new_ops": f.ops.len() - query.initial_ops,
        "entries": f.log.len(),
        "micros": started.elapsed().as_micros() as u64,
    }}));
    if m == Mode::Verify {
        VERIFY.with(|slot| *slot.borrow_mut() = Some(f));
        return b"v".to_vec();
    }
    encode_log(&f)
}

/// Verify mode: the decompiler's own final state against the worker's.
pub fn answer_dump(payload: &[u8]) -> Vec<u8> {
    let Some(ours) = VERIFY.with(|slot| slot.borrow_mut().take()) else {
        return b"n".to_vec();
    };
    let theirs = match super::ir::decode_merge_dump(payload) {
        Ok(d) => d,
        Err(reason) => {
            log_line(serde_json::json!({"merge_mismatch": {"decode": reason}}));
            return b"n".to_vec();
        }
    };
    let mut problems: Vec<String> = Vec::new();
    // Ops, block by block.
    if ours.blocks.len() != theirs.blocks.len() {
        problems.push(format!("blocks {} {}", ours.blocks.len(), theirs.blocks.len()));
    }
    for (b, (mine, other)) in ours.blocks.iter().zip(theirs.blocks.iter()).enumerate() {
        let mine: Vec<DumpOp> = mine.ops.iter().map(|&o| ours.dump_op(o)).collect();
        if mine != *other {
            let at = mine.iter().zip(other.iter()).position(|(a, b)| a != b).unwrap_or(mine.len().min(other.len()));
            problems.push(format!(
                "ops block {b} (len {} vs {}) at {at}: worker {:?} decompiler {:?}",
                mine.len(),
                other.len(),
                mine.get(at),
                other.get(at)
            ));
        }
    }
    // Varnodes: the partition, explicit/implied.
    let mut mine: std::collections::BTreeMap<u32, (u32, bool, bool, bool)> = Default::default();
    for vn in &ours.vns {
        if vn.gone || vn.high == model::NO_HIGH || vn.is_annotation() {
            continue;
        }
        let high = &ours.highs[vn.high];
        let rep = high.inst.iter().map(|&i| ours.vns[i].create).min().unwrap_or(vn.create);
        mine.insert(vn.create, (rep, vn.is_explicit(), vn.is_implied(), vn.flags & vf::INDIRECTONLY != 0));
    }
    let mut diffs = 0;
    for (create, rep, ex, im, io) in &theirs.vns {
        match mine.get(create) {
            Some(m) if m == &(*rep, *ex, *im, *io) => {}
            other => {
                diffs += 1;
                if diffs <= 3 {
                    problems.push(format!("varnode {create}: worker {other:?} decompiler {:?}", (rep, ex, im, io)));
                }
            }
        }
    }
    if mine.len() != theirs.vns.len() {
        problems.push(format!("varnode count {} {}", mine.len(), theirs.vns.len()));
    }
    if diffs > 3 {
        problems.push(format!("{diffs} varnodes differ"));
    }
    let my_loops: Vec<(usize, usize, Option<u64>, Option<u64>)> = ours
        .loops
        .iter()
        .map(|l| (l.head, l.tail, l.init.map(|o| ours.ops[o].time), l.iter.map(|o| ours.ops[o].time)))
        .collect();
    if my_loops != theirs.loops {
        problems.push(format!("loops worker {my_loops:?} decompiler {:?}", theirs.loops));
    }
    if problems.is_empty() {
        log_line(serde_json::json!({"merge_verified": 1, "address": ours.address}));
    } else {
        log_line(serde_json::json!({"merge_mismatch": {"address": ours.address, "problems": problems}}));
    }
    b"n".to_vec()
}

/// An op as the verify dump compares it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DumpOp {
    pub time: u64,
    pub code: u32,
    pub non_printing: bool,
    pub special_print: bool,
    pub out: Option<u32>,
    pub ins: Vec<u32>,
}

impl Func {
    fn dump_op(&self, op: usize) -> DumpOp {
        let o = &self.ops[op];
        DumpOp {
            time: o.time,
            code: o.code,
            non_printing: o.flags & model::pf::NONPRINTING != 0,
            special_print: o.addl & model::pf::SPECIAL_PRINT != 0,
            out: o.out.map(|v| self.vns[v].create),
            ins: o.ins.iter().map(|&v| self.vns[v].create).collect(),
        }
    }
}

/// The decompiler's final state, as `answer_dump` reads it.
pub struct Dump {
    pub blocks: Vec<Vec<DumpOp>>,
    pub vns: Vec<(u32, u32, bool, bool, bool)>,
    pub loops: Vec<(usize, usize, Option<u64>, Option<u64>)>,
}
