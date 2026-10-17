//! Which printings the near-miss search tries, and in which order.
//!
//! Every knob is one that already exists in the decompiler's printing path; the
//! search invents no rule. A variant is a set of knobs on different axes:
//!
//! * `ROMWRIGHT_MERGE_VARIANT` (stage 3, docs/merge-port.md section 5):
//!   `adjacent`, `datatype`, `copy`, `dominant`, `hideshadow` off, `maxref=N`,
//!   `maxdup=N`: which values share a C variable and which print as
//!   sub-expressions.
//! * `ROMWRIGHT_RUST_CASTS_CALLS=cast`: an undeclared callee's prototype is read
//!   off the calls as the casts typed them (the casting rule of the previous printer).
//! * `ROMWRIGHT_RUST_STRUCTURING` (`printc/structure.rs`): `none` runs no
//!   goto-removing model, so the gotos of the decompiler's own structure stay;
//!   `all,no_arm_order` prints `if`/`else` arms in the decompiler's order
//!   instead of code order.
//!
//! The order of [`SINGLES`] is only what a small budget keeps: cheapest and most
//! often productive on the Stage 3 near-miss smoke first. Combinations are made
//! from what the single knobs did on this function, never from a fitted table.

use std::collections::BTreeMap;

/// One switch of the printing path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Knob {
    /// A `ROMWRIGHT_MERGE_VARIANT` item, e.g. `datatype=off`.
    Merge(&'static str),
    /// `ROMWRIGHT_RUST_CASTS_CALLS=cast`.
    CallsCast,
    /// A `ROMWRIGHT_RUST_STRUCTURING` value (`none`, `all,no_arm_order`).
    Structuring(&'static str),
}

impl Knob {
    /// The axis the knob sits on: two knobs of one axis never combine.
    pub fn axis(self) -> &'static str {
        match self {
            Knob::Merge(item) => item.split('=').next().unwrap_or(item),
            Knob::CallsCast => "calls",
            Knob::Structuring(_) => "structuring",
        }
    }

    pub fn label(self) -> String {
        match self {
            Knob::Merge(item) => item.to_string(),
            Knob::CallsCast => "calls=cast".to_string(),
            Knob::Structuring(value) => format!("structuring={}", value.trim_start_matches("all,")),
        }
    }
}

/// A printing of the function: the stock one has no knobs.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct PrintVariant {
    pub knobs: Vec<Knob>,
}

impl PrintVariant {
    pub fn stock() -> PrintVariant {
        PrintVariant::default()
    }

    pub fn of(knobs: &[Knob]) -> PrintVariant {
        PrintVariant { knobs: knobs.to_vec() }
    }

    pub fn is_stock(&self) -> bool {
        self.knobs.is_empty()
    }

    /// `default`, or the knobs joined by `+`.
    pub fn label(&self) -> String {
        if self.knobs.is_empty() {
            "default".into()
        } else {
            self.knobs.iter().map(|k| k.label()).collect::<Vec<_>>().join("+")
        }
    }

    /// The environment the decompiler worker gets (empty for the stock printing).
    pub fn env(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        let merge: Vec<&str> = self.knobs.iter().filter_map(|k| if let Knob::Merge(item) = k { Some(*item) } else { None }).collect();
        if !merge.is_empty() {
            out.push(("ROMWRIGHT_MERGE_VARIANT".to_string(), merge.join(",")));
        }
        if self.knobs.contains(&Knob::CallsCast) {
            out.push(("ROMWRIGHT_RUST_CASTS_CALLS".to_string(), "cast".to_string()));
        }
        if let Some(Knob::Structuring(value)) = self.knobs.iter().find(|k| matches!(k, Knob::Structuring(_))) {
            out.push(("ROMWRIGHT_RUST_STRUCTURING".to_string(), (*value).to_string()));
        }
        out
    }

    /// The `ROMWRIGHT_*` assignments as `K=V` words (for a harness `--env`).
    pub fn env_words(&self) -> Vec<String> {
        self.env().into_iter().map(|(k, v)| format!("{k}={v}")).collect()
    }
}

/// Every single-knob variant, in the order a budget keeps them.
pub const SINGLES: [Knob; 14] = [
    Knob::Merge("datatype=off"),
    Knob::Merge("maxref=1"),
    Knob::Merge("adjacent=off"),
    Knob::Merge("copy=off"),
    Knob::Merge("dominant=off"),
    Knob::Merge("hideshadow=off"),
    Knob::Merge("maxdup=1"),
    Knob::Merge("maxref=3"),
    Knob::Merge("maxref=4"),
    Knob::Merge("maxdup=3"),
    Knob::Merge("maxdup=4"),
    Knob::CallsCast,
    Knob::Structuring("none"),
    Knob::Structuring("all,no_arm_order"),
];

/// The default budget: every single knob and ten combinations.
pub const DEFAULT_BUDGET: usize = 24;

/// How many single-knob outcomes the pair stage combines.
const PAIR_POOL: usize = 4;

/// The single-knob variants a budget of `budget` variants (the stock one not counted) keeps.
pub fn singles(budget: usize) -> Vec<PrintVariant> {
    SINGLES.iter().take(budget).map(|k| PrintVariant::of(&[*k])).collect()
}

/// What one tried variant did, as far as the combination stage needs to know.
#[derive(Clone, Debug)]
pub struct Outcome {
    pub variant: PrintVariant,
    /// Its printed C differs from every earlier variant's.
    pub distinct: bool,
    /// Ranking key of its score: see `Score::key`.
    pub key: (bool, bool, f64, i64),
}

/// The combinations to try after the single knobs, at most `room` of them.
///
/// 1. the speculative-merge knobs together (`adjacent=off+datatype=off`, then with `copy=off`);
/// 2. pairs, then the triple, of the best single knobs on distinct axes: those whose
///    printed C differed from the stock one and which scored no worse than it,
///    best first (`PAIR_POOL` of them).
///
/// Variants already tried (`tried`) are skipped.
pub fn combinations(stock: &Outcome, singles: &[Outcome], tried: &[PrintVariant], room: usize) -> Vec<PrintVariant> {
    let mut out: Vec<PrintVariant> = Vec::new();
    let push = |variant: PrintVariant, out: &mut Vec<PrintVariant>| {
        if variant.knobs.len() > 1 && !tried.contains(&variant) && !out.contains(&variant) {
            out.push(variant);
        }
    };
    let distinct_merge = |item: &'static str| singles.iter().any(|o| o.distinct && o.variant.knobs == [Knob::Merge(item)]);
    if distinct_merge("adjacent=off") && distinct_merge("datatype=off") {
        push(PrintVariant::of(&[Knob::Merge("adjacent=off"), Knob::Merge("datatype=off")]), &mut out);
        if distinct_merge("copy=off") {
            push(PrintVariant::of(&[Knob::Merge("adjacent=off"), Knob::Merge("datatype=off"), Knob::Merge("copy=off")]), &mut out);
        }
    }
    let mut pool: Vec<&Outcome> = singles.iter().filter(|o| o.distinct && cmp_key(&o.key, &stock.key) != std::cmp::Ordering::Less).collect();
    pool.sort_by(|a, b| cmp_key(&b.key, &a.key));
    pool.truncate(PAIR_POOL);
    for i in 0..pool.len() {
        for j in i + 1..pool.len() {
            let (a, b) = (pool[i].variant.knobs[0], pool[j].variant.knobs[0]);
            if a.axis() != b.axis() {
                push(PrintVariant::of(&[a, b]), &mut out);
            }
        }
    }
    if let [a, b, c, ..] = pool[..] {
        let knobs = [a.variant.knobs[0], b.variant.knobs[0], c.variant.knobs[0]];
        let axes: std::collections::BTreeSet<&str> = knobs.iter().map(|k| k.axis()).collect();
        if axes.len() == 3 {
            push(PrintVariant::of(&knobs), &mut out);
        }
    }
    out.truncate(room);
    out
}

pub fn cmp_key(a: &(bool, bool, f64, i64), b: &(bool, bool, f64, i64)) -> std::cmp::Ordering {
    a.0.cmp(&b.0)
        .then(a.1.cmp(&b.1))
        .then(a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal))
        .then(a.3.cmp(&b.3))
}

/// Parses a variant label (`default`, `a+b`) back; used by the harness plan
/// round trip and the tests.
pub fn parse_label(label: &str) -> Result<PrintVariant, String> {
    if label == "default" {
        return Ok(PrintVariant::stock());
    }
    let mut known: BTreeMap<String, Knob> = SINGLES.iter().map(|k| (k.label(), *k)).collect();
    let mut knobs = Vec::new();
    for part in label.split('+') {
        knobs.push(known.remove(part).ok_or_else(|| format!("unknown printing knob `{part}`"))?);
    }
    Ok(PrintVariant { knobs })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(knob: Knob, distinct: bool, percent: f64) -> Outcome {
        Outcome { variant: PrintVariant::of(&[knob]), distinct, key: (false, true, percent, 0) }
    }

    #[test]
    fn labels_round_trip_and_env_is_per_axis() {
        for single in singles(DEFAULT_BUDGET) {
            assert_eq!(parse_label(&single.label()).unwrap(), single);
        }
        let v = PrintVariant::of(&[Knob::Merge("maxref=1"), Knob::Merge("datatype=off"), Knob::CallsCast, Knob::Structuring("all,no_arm_order")]);
        assert_eq!(parse_label(&v.label()).unwrap().knobs.len(), 4);
        assert_eq!(
            v.env(),
            vec![
                ("ROMWRIGHT_MERGE_VARIANT".to_string(), "maxref=1,datatype=off".to_string()),
                ("ROMWRIGHT_RUST_CASTS_CALLS".to_string(), "cast".to_string()),
                ("ROMWRIGHT_RUST_STRUCTURING".to_string(), "all,no_arm_order".to_string()),
            ]
        );
        assert!(PrintVariant::stock().env().is_empty());
    }

    #[test]
    fn combinations_use_distinct_axes_and_skip_what_was_tried() {
        let stock = Outcome { variant: PrintVariant::stock(), distinct: true, key: (false, true, 80.0, 0) };
        let singles = vec![
            outcome(Knob::Merge("datatype=off"), true, 85.0),
            outcome(Knob::Merge("maxref=1"), true, 90.0),
            outcome(Knob::Merge("maxref=3"), true, 82.0),
            outcome(Knob::CallsCast, false, 99.0),
            outcome(Knob::Merge("copy=off"), true, 70.0),
        ];
        let tried: Vec<PrintVariant> = singles.iter().map(|o| o.variant.clone()).collect();
        let pairs = combinations(&stock, &singles, &tried, 10);
        assert!(pairs.iter().all(|p| p.knobs.windows(2).all(|w| w[0].axis() != w[1].axis())));
        assert!(pairs.contains(&PrintVariant::of(&[Knob::Merge("maxref=1"), Knob::Merge("datatype=off")])));
        // calls=cast printed the same C: not combined; copy=off scored worse than stock: not combined.
        assert!(pairs.iter().all(|p| !p.knobs.contains(&Knob::CallsCast) && !p.knobs.contains(&Knob::Merge("copy=off"))));
        assert!(combinations(&stock, &singles, &tried, 1).len() <= 1);
    }
}
