//! The printing-variant knob: which of the merge and explicit/implied choices
//! the decompiler makes may be varied for one function, so a search over
//! alternative C printings (the near-miss search of docs/merge-port.md
//! section 5) can drive them. The default is the stock behaviour.

use super::model::Func;
use std::collections::HashMap;
use std::sync::OnceLock;

/// A value, stably named across variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VarRef {
    /// The value an op writes, by the op's `PcodeOp::getTime`.
    Def(u64),
    /// A function input, by storage: space index, offset, size.
    Input { space: u32, offset: u64, size: u32 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Variant {
    /// `ActionMergeAdjacent`.
    pub adjacent: bool,
    /// `ActionMergeType`.
    pub datatype: bool,
    /// `ActionMergeCopy`.
    pub copy: bool,
    /// `ActionDominantCopy`.
    pub dominant: bool,
    /// `ActionHideShadow`.
    pub hide_shadow: bool,
    /// `Architecture::max_implied_ref` (stock 2).
    pub max_implied_ref: Option<u32>,
    /// `Architecture::max_term_duplication` (stock 2).
    pub max_term_duplication: Option<u32>,
    /// Values forced to be a variable of their own.
    pub explicit: Vec<VarRef>,
    /// Pairs of values a speculative merge may not put in one variable.
    pub separate: Vec<(VarRef, VarRef)>,
}

impl Default for Variant {
    fn default() -> Self {
        Variant {
            adjacent: true,
            datatype: true,
            copy: true,
            dominant: true,
            hide_shadow: true,
            max_implied_ref: None,
            max_term_duplication: None,
            explicit: Vec::new(),
            separate: Vec::new(),
        }
    }
}

impl std::fmt::Display for VarRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VarRef::Def(time) => write!(f, "t{time}"),
            VarRef::Input { space, offset, size } => write!(f, "i{space}:{offset:#x}:{size}"),
        }
    }
}

impl VarRef {
    pub fn parse(text: &str) -> Result<VarRef, String> {
        if let Some(rest) = text.strip_prefix('t') {
            return rest.parse().map(VarRef::Def).map_err(|_| format!("variant: bad value {text}"));
        }
        if let Some(rest) = text.strip_prefix('i') {
            let parts: Vec<&str> = rest.split(':').collect();
            if let [space, offset, size] = parts[..] {
                let offset = offset.strip_prefix("0x").map_or_else(|| offset.parse(), |h| u64::from_str_radix(h, 16));
                if let (Ok(space), Ok(offset), Ok(size)) = (space.parse(), offset, size.parse()) {
                    return Ok(VarRef::Input { space, offset, size });
                }
            }
        }
        Err(format!("variant: bad value {text}"))
    }
}

fn flag(value: &str, key: &str) -> Result<bool, String> {
    match value {
        "on" | "1" | "true" => Ok(true),
        "off" | "0" | "false" => Ok(false),
        _ => Err(format!("variant: {key} expects on or off")),
    }
}

impl Variant {
    /// `default`, or comma-separated `key=value`: `adjacent`, `datatype`,
    /// `copy`, `dominant`, `hideshadow` (`on`/`off`), `maxref`, `maxdup`
    /// (numbers), `explicit=t12+t40+i3:0x10:4`, `separate=t12:t40+t5:t7`.
    pub fn parse(spec: &str) -> Result<Variant, String> {
        let mut v = Variant::default();
        for item in spec.split(',').map(str::trim).filter(|s| !s.is_empty() && *s != "default") {
            let (key, value) = item.split_once('=').ok_or_else(|| format!("variant: expected key=value, got {item}"))?;
            match key {
                "adjacent" => v.adjacent = flag(value, key)?,
                "datatype" => v.datatype = flag(value, key)?,
                "copy" => v.copy = flag(value, key)?,
                "dominant" => v.dominant = flag(value, key)?,
                "hideshadow" => v.hide_shadow = flag(value, key)?,
                "maxref" => v.max_implied_ref = Some(value.parse().map_err(|_| "variant: maxref".to_string())?),
                "maxdup" => v.max_term_duplication = Some(value.parse().map_err(|_| "variant: maxdup".to_string())?),
                "explicit" => {
                    for part in value.split('+').filter(|s| !s.is_empty()) {
                        v.explicit.push(VarRef::parse(part)?);
                    }
                }
                "separate" => {
                    for part in value.split('+').filter(|s| !s.is_empty()) {
                        let (a, b) = part.split_once('~').ok_or("variant: separate expects a~b")?;
                        v.separate.push((VarRef::parse(a)?, VarRef::parse(b)?));
                    }
                }
                _ => return Err(format!("variant: unknown key {key}")),
            }
        }
        Ok(v)
    }

    pub fn is_default(&self) -> bool {
        *self == Variant::default()
    }

    /// The spec `parse` reads back.
    pub fn spec(&self) -> String {
        let d = Variant::default();
        let mut parts = Vec::new();
        for (name, on, stock) in [
            ("adjacent", self.adjacent, d.adjacent),
            ("datatype", self.datatype, d.datatype),
            ("copy", self.copy, d.copy),
            ("dominant", self.dominant, d.dominant),
            ("hideshadow", self.hide_shadow, d.hide_shadow),
        ] {
            if on != stock {
                parts.push(format!("{name}={}", if on { "on" } else { "off" }));
            }
        }
        if let Some(n) = self.max_implied_ref {
            parts.push(format!("maxref={n}"));
        }
        if let Some(n) = self.max_term_duplication {
            parts.push(format!("maxdup={n}"));
        }
        if !self.explicit.is_empty() {
            let list: Vec<String> = self.explicit.iter().map(ToString::to_string).collect();
            parts.push(format!("explicit={}", list.join("+")));
        }
        if !self.separate.is_empty() {
            let list: Vec<String> = self.separate.iter().map(|(a, b)| format!("{a}~{b}")).collect();
            parts.push(format!("separate={}", list.join("+")));
        }
        if parts.is_empty() { "default".into() } else { parts.join(",") }
    }
}

enum Source {
    Inline(Variant),
    Map(HashMap<u64, Variant>, Option<Variant>),
}

fn from_env() -> &'static Option<Source> {
    static SOURCE: OnceLock<Option<Source>> = OnceLock::new();
    SOURCE.get_or_init(|| {
        let value = std::env::var("ROMWRIGHT_MERGE_VARIANT").ok()?;
        if value.is_empty() {
            return None;
        }
        if let Some(path) = value.strip_prefix('@') {
            let text = match std::fs::read_to_string(path) {
                Ok(text) => text,
                Err(err) => {
                    eprintln!("ROMWRIGHT_MERGE_VARIANT: {path}: {err}");
                    return None;
                }
            };
            let json: serde_json::Value = match serde_json::from_str(&text) {
                Ok(json) => json,
                Err(err) => {
                    eprintln!("ROMWRIGHT_MERGE_VARIANT: {path}: {err}");
                    return None;
                }
            };
            let mut map = HashMap::new();
            let mut star = None;
            for (key, spec) in json.as_object()? {
                let Some(spec) = spec.as_str() else { continue };
                let Ok(variant) = Variant::parse(spec) else {
                    eprintln!("ROMWRIGHT_MERGE_VARIANT: {key}: bad spec {spec}");
                    continue;
                };
                if key == "*" {
                    star = Some(variant);
                } else if let Ok(addr) = u64::from_str_radix(key.trim_start_matches("0x"), 16) {
                    map.insert(addr, variant);
                }
            }
            return Some(Source::Map(map, star));
        }
        match Variant::parse(&value) {
            Ok(v) => Some(Source::Inline(v)),
            Err(err) => {
                eprintln!("ROMWRIGHT_MERGE_VARIANT: {err}");
                None
            }
        }
    })
}

thread_local! {
    static OVERRIDES: std::cell::RefCell<HashMap<u64, Variant>> = Default::default();
}

/// Sets the variants an in-process caller wants (function address -> variant); replaces earlier ones.
pub fn set_variants(map: HashMap<u64, Variant>) {
    OVERRIDES.with(|slot| *slot.borrow_mut() = map);
}

/// The variant for the function at `address`: an in-process override, then
/// `ROMWRIGHT_MERGE_VARIANT`, then the stock behaviour.
pub fn for_function(address: u64) -> Variant {
    if let Some(v) = OVERRIDES.with(|slot| slot.borrow().get(&address).cloned()) {
        return v;
    }
    match from_env() {
        Some(Source::Inline(v)) => v.clone(),
        Some(Source::Map(map, star)) => map.get(&address).or(star.as_ref()).cloned().unwrap_or_default(),
        None => Variant::default(),
    }
}

impl Func {
    fn resolve(&self, r: VarRef) -> Option<usize> {
        (0..self.vns.len()).find(|&v| {
            let vn = &self.vns[v];
            match r {
                VarRef::Def(time) => vn.def.is_some_and(|d| self.ops[d].time == time && vn.is_written()),
                VarRef::Input { space, offset, size } => {
                    vn.is_input() && vn.addr.space == space && vn.addr.offset == offset && vn.size == size
                }
            }
        })
    }

    /// The varnodes the variant forces explicit.
    pub fn variant_explicit(&self) -> Vec<usize> {
        self.variant.explicit.iter().filter_map(|&r| self.resolve(r)).collect()
    }

    /// Resolves the `separate` pairs once the function is decoded.
    pub fn resolve_variant(&mut self) {
        let pairs: Vec<(VarRef, VarRef)> = self.variant.separate.clone();
        for (a, b) in pairs {
            if let (Some(x), Some(y)) = (self.resolve(a), self.resolve(b)) {
                self.forbid.insert((x, y));
                self.forbid.insert((y, x));
            }
        }
    }

    /// Does the variant forbid a speculative merge of these two variables?
    pub fn variant_separates(&self, ha: usize, hb: usize) -> bool {
        if self.forbid.is_empty() {
            return false;
        }
        self.highs[ha]
            .inst
            .iter()
            .any(|&x| self.highs[hb].inst.iter().any(|&y| self.forbid.contains(&(x, y))))
    }
}
