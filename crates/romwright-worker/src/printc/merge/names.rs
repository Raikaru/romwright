//! `ActionNameVars`' default names (`Scope::buildDefaultName`,
//! `ScopeInternal::buildVariableName`, `ScopeLocal::buildVariableName`),
//! ported from the pinned Ghidra 12.1.3 decompiler (Apache-2.0).
//!
//! The decompiler links symbols and applies the recommended names (locked
//! callee parameter names, jump-table names) itself, then asks here for the
//! name of every variable that is still unnamed, in the order it visits them
//! (marker 3, docs/merge-port.md section 6). The scope's own uniqueness check
//! (`makeNameUnique`) stays with the decompiler: an answer says whether it
//! must be applied. Only the `iVar3` family is made unique here, against the
//! names of the local scope, because its counter depends on the outcome.

use super::{log_line, put};
use std::collections::HashSet;

/// `Varnode::varnode_flags` the naming reads.
const INPUT: u32 = 0x08;
const PERSIST: u32 = 0x4000;
const ADDRTIED: u32 = 0x8000;
const UNAFFECTED: u32 = 0x10000;
const INDIRECT_CREATION: u32 = 0x400000;
const RETURN_ADDRESS: u32 = 0x800000;

/// One unnamed variable, with the facts `buildDefaultName` computes from the
/// varnode, symbol and scope (those need the decompiler's objects).
#[derive(Clone, Debug, Default)]
pub struct NameEntry {
    pub flags: u32,
    /// The parameter index (1-based), or -1 for an irregular input.
    pub index: i32,
    pub has_type: bool,
    /// `Datatype::printNameBase`.
    pub type_base: String,
    pub type_size: u32,
    pub space_name: String,
    pub offset: u64,
    pub addr_size: u32,
    /// `AddrSpace::byteToAddress(offset, wordsize)`.
    pub word_offset: u64,
    /// `Translate::getRegisterName` of the storage.
    pub register: String,
    /// `ScopeLocal::buildVariableName`'s stack form applies.
    pub stack_local: bool,
    pub stack_start: i64,
    pub stack_unusual: bool,
}

pub struct NamesQuery {
    pub address: u64,
    pub base: i32,
    pub local_names: Vec<String>,
    pub entries: Vec<NameEntry>,
}

fn capitalize(space: &str) -> String {
    let mut chars = space.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// The name `ScopeLocal`/`ScopeInternal::buildVariableName` builds, and whether
/// the scope's `makeNameUnique` must still be applied to it.
pub fn build_name(e: &NameEntry, base: &mut i32, names: &HashSet<String>) -> (String, bool) {
    let ct = if e.has_type { e.type_base.as_str() } else { "" };
    let flags = e.flags;
    if flags & (ADDRTIED | PERSIST) == ADDRTIED && e.stack_local {
        let mut s = String::from(ct);
        s.push_str(&capitalize(&e.space_name));
        let mut start = e.stack_start;
        if start <= 0 {
            s.push('X');
            start = -start;
        } else if e.stack_unusual {
            s.push('Y');
        }
        s.push_str(&format!("_{start:x}"));
        return (s, true);
    }
    let raw = if flags & UNAFFECTED != 0 {
        if flags & RETURN_ADDRESS != 0 {
            "unaff_retaddr".to_string()
        } else if e.register.is_empty() {
            format!("unaff_{:08x}", e.offset)
        } else {
            format!("unaff_{}", e.register)
        }
    } else if flags & PERSIST != 0 {
        if !e.register.is_empty() {
            e.register.clone()
        } else {
            format!(
                "{ct}{}{:0width$x}",
                capitalize(&e.space_name),
                e.word_offset,
                width = 2 * e.addr_size as usize
            )
        }
    } else if flags & INPUT != 0 && e.index < 0 {
        if e.register.is_empty() {
            format!("in_{}_{:08x}", e.space_name, e.offset)
        } else {
            format!("in_{}", e.register)
        }
    } else if flags & INPUT != 0 {
        format!("param_{}", e.index)
    } else if flags & ADDRTIED != 0 {
        format!(
            "{ct}{}{:0width$x}",
            capitalize(&e.space_name),
            e.word_offset,
            width = 2 * e.addr_size as usize
        )
    } else if flags & INDIRECT_CREATION != 0 {
        if e.register.is_empty() {
            "extraout_var".to_string()
        } else {
            format!("extraout_{}", e.register)
        }
    } else {
        let s = format!("{ct}Var{}", *base);
        *base += 1;
        if names.contains(&s) {
            for _ in 0..10 {
                let s2 = format!("{ct}Var{}", *base);
                *base += 1;
                if !names.contains(&s2) {
                    return (s2, false);
                }
            }
        }
        s
    };
    (raw, true)
}

/// Marker 3: the default names, in the order the decompiler visits the variables.
pub fn answer_names(payload: &[u8]) -> Vec<u8> {
    if matches!(std::env::var("ROMWRIGHT_RUST_NAMES").as_deref(), Ok("off" | "0")) {
        return b"n".to_vec();
    }
    let query = match super::super::ir::decode_names_query(payload) {
        Ok(q) => q,
        Err(reason) => {
            log_line(serde_json::json!({"names_declined": format!("decode:{reason}")}));
            return b"n".to_vec();
        }
    };
    let mut names: HashSet<String> = query.local_names.iter().cloned().collect();
    let mut base = query.base;
    let mut out;
    let mut results = Vec::with_capacity(query.entries.len());
    for entry in &query.entries {
        let (name, unique) = build_name(entry, &mut base, &names);
        names.insert(name.clone());
        results.push((name, unique));
    }
    out = vec![b'o'];
    put(&mut out, base.max(0) as u64);
    put(&mut out, results.len() as u64);
    for (name, unique) in &results {
        put(&mut out, u64::from(*unique));
        put(&mut out, name.len() as u64);
        for byte in name.bytes() {
            put(&mut out, u64::from(byte));
        }
    }
    log_line(serde_json::json!({"names_ok": {"address": query.address, "names": results.len()}}));
    out
}
