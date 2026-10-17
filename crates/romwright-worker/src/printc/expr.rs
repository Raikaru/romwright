//! Structural expression helpers over [`Expr`]: equality, negation and
//! implication between conditions.
//!
//! The printer IR carries every expression twice: as PrintC's emit fragments
//! (text, for the printer) and as an [`Expr`] tree (opcodes over varnodes,
//! for passes). A pass that reasons about conditions -- a jump-threading
//! reversal that must know a test's outcome on a path, a compare chain that
//! is a lowered switch -- works on the trees here. Nothing in this module
//! prints.
//!
//! Soundness is the caller's: two trees that are [`same`] compute the same
//! value only when nothing they read changed in between. [`Facts`] therefore
//! carries what is known *at one program point* and [`Facts::kill`] drops
//! what a statement can change.

use super::ir::{Effect, Expr, Storage};

/// `PcodeOp::code` values the helpers know (opcodes.hh).
pub mod code {
    pub const COPY: u32 = 1;
    pub const LOAD: u32 = 2;
    pub const CBRANCH: u32 = 5;
    pub const INT_EQUAL: u32 = 11;
    pub const INT_NOTEQUAL: u32 = 12;
    pub const INT_SLESS: u32 = 13;
    pub const INT_SLESSEQUAL: u32 = 14;
    pub const INT_LESS: u32 = 15;
    pub const INT_LESSEQUAL: u32 = 16;
    pub const BOOL_NEGATE: u32 = 37;
    pub const BOOL_AND: u32 = 39;
    pub const BOOL_OR: u32 = 40;
}

/// Whether two expressions are the same computation over the same
/// variables: structure and constants equal, variables the same C variable
/// (HighVariable) or, without one, the same SSA value.
pub fn same(a: &Expr, b: &Expr) -> bool {
    match (a, b) {
        (Expr::Opaque, _) | (_, Expr::Opaque) => false,
        (
            Expr::Const { size, value },
            Expr::Const {
                size: other_size,
                value: other_value,
            },
        ) => size == other_size && value == other_value,
        (
            Expr::Var {
                size,
                ssa,
                high,
                storage,
            },
            Expr::Var {
                size: other_size,
                ssa: other_ssa,
                high: other_high,
                storage: other_storage,
            },
        ) => {
            size == other_size
                && storage == other_storage
                && if *high != 0 && *other_high != 0 {
                    high == other_high
                } else {
                    ssa == other_ssa
                }
        }
        (
            Expr::Op { code, args },
            Expr::Op {
                code: other_code,
                args: other_args,
            },
        ) => {
            code == other_code
                && args.len() == other_args.len()
                && args.iter().zip(other_args).all(|(x, y)| same(x, y))
        }
        _ => false,
    }
}

/// No part of the tree was cut off by the exporter.
pub fn complete(expr: &Expr) -> bool {
    match expr {
        Expr::Opaque => false,
        Expr::Op { args, .. } => args.iter().all(complete),
        _ => true,
    }
}

/// What evaluating an expression reads.
#[derive(Debug, Default)]
pub struct Reads {
    /// Variables read: (HighVariable or 0, SSA value, storage).
    pub vars: Vec<(u32, u64, Storage)>,
    /// Memory read through a `LOAD`.
    pub loads: bool,
}

pub fn reads(expr: &Expr, into: &mut Reads) {
    match expr {
        Expr::Var {
            ssa, high, storage, ..
        } => into.vars.push((*high, *ssa, *storage)),
        Expr::Op { code: code::LOAD, args } => {
            into.loads = true;
            args.iter().for_each(|arg| reads(arg, into));
        }
        Expr::Op { args, .. } => args.iter().for_each(|arg| reads(arg, into)),
        _ => {}
    }
}

/// Whether `written` (a statement's output variable) is the variable `read`
/// names.
fn aliases(written: &Expr, high: u32, ssa: u64) -> bool {
    match written {
        Expr::Var {
            high: written_high,
            ssa: written_ssa,
            ..
        } => {
            if high != 0 && *written_high != 0 {
                high == *written_high
            } else {
                ssa == *written_ssa
            }
        }
        _ => false,
    }
}

/// Whether executing `effect` may change a value `reads` described.
pub fn clobbers(effect: &Effect, reads: &Reads) -> bool {
    if reads.loads && (effect.calls || effect.stores) {
        return true;
    }
    reads.vars.iter().any(|(high, ssa, storage)| {
        effect
            .out
            .as_ref()
            .is_some_and(|written| aliases(written, *high, *ssa))
            || ((effect.calls || effect.stores) && (storage.aliased || storage.class == 2))
    })
}

// ---------------------------------------------------------------------------
// Value sets of a compared expression.

/// Inclusive intervals of unsigned residues, sorted and disjoint.
type Set = Vec<(u128, u128)>;

/// What a comparison against a constant says about the other operand.
#[derive(Clone, Debug)]
struct Literal {
    /// The compared expression.
    key: Expr,
    bits: u32,
    /// The values `key` takes when the literal holds.
    set: Set,
}

fn max_of(bits: u32) -> u128 {
    if bits >= 128 {
        u128::MAX
    } else {
        (1u128 << bits) - 1
    }
}

fn complement(set: &Set, bits: u32) -> Set {
    let max = max_of(bits);
    let mut out = Vec::new();
    let mut next = 0u128;
    for &(lo, hi) in set {
        if lo > next {
            out.push((next, lo - 1));
        }
        next = hi.saturating_add(1);
        if hi == max {
            return out;
        }
    }
    if next <= max {
        out.push((next, max));
    }
    out
}

fn intersect(a: &Set, b: &Set) -> Set {
    let mut out = Vec::new();
    for &(alo, ahi) in a {
        for &(blo, bhi) in b {
            let (lo, hi) = (alo.max(blo), ahi.min(bhi));
            if lo <= hi {
                out.push((lo, hi));
            }
        }
    }
    out.sort_unstable();
    out
}

fn subset(a: &Set, b: &Set) -> bool {
    a.iter()
        .all(|&(lo, hi)| b.iter().any(|&(blo, bhi)| blo <= lo && hi <= bhi))
}

/// A signed interval `[lo, hi]` of an n-bit value as unsigned residues.
fn signed_interval(lo: i128, hi: i128, bits: u32) -> Set {
    let modulus = 1i128 << bits;
    let (min, max) = (-(modulus >> 1), (modulus >> 1) - 1);
    let (lo, hi) = (lo.max(min), hi.min(max));
    if lo > hi {
        return Vec::new();
    }
    let mut out = Vec::new();
    if lo >= 0 {
        out.push((lo as u128, hi as u128));
    } else if hi < 0 {
        out.push(((lo + modulus) as u128, (hi + modulus) as u128));
    } else {
        out.push((0, hi as u128));
        out.push(((lo + modulus) as u128, (modulus - 1) as u128));
    }
    out.sort_unstable();
    out
}

fn signed_value(value: u64, bits: u32) -> i128 {
    let value = value as i128;
    if value >> (bits - 1) & 1 == 1 {
        value - (1i128 << bits)
    } else {
        value
    }
}

/// The literal `(a op b) == truth` as a set on its non-constant operand,
/// for `op` a comparison and exactly one operand a constant.
fn literal(code: u32, a: &Expr, b: &Expr, truth: bool) -> Option<Literal> {
    let (key, c, key_left, size) = match (a, b) {
        (Expr::Const { .. }, Expr::Const { .. }) => return None,
        (key, Expr::Const { size, value }) => (key, *value, true, *size),
        (Expr::Const { size, value }, key) => (key, *value, false, *size),
        _ => return None,
    };
    let bits = size * 8;
    if bits == 0 || bits > 64 || !complete(key) {
        return None;
    }
    let max = max_of(bits);
    let c = c as u128 & max;
    let signed_c = signed_value(c as u64, bits);
    let set: Set = match (code, key_left) {
        (code::INT_EQUAL, _) => vec![(c, c)],
        (code::INT_NOTEQUAL, _) => complement(&vec![(c, c)], bits),
        // x < c, c > x
        (code::INT_LESS, true) => {
            if c == 0 {
                Vec::new()
            } else {
                vec![(0, c - 1)]
            }
        }
        // c < x
        (code::INT_LESS, false) => {
            if c == max {
                Vec::new()
            } else {
                vec![(c + 1, max)]
            }
        }
        (code::INT_LESSEQUAL, true) => vec![(0, c)],
        (code::INT_LESSEQUAL, false) => vec![(c, max)],
        (code::INT_SLESS, true) => signed_interval(i128::MIN / 2, signed_c - 1, bits),
        (code::INT_SLESS, false) => signed_interval(signed_c + 1, i128::MAX / 2, bits),
        (code::INT_SLESSEQUAL, true) => signed_interval(i128::MIN / 2, signed_c, bits),
        (code::INT_SLESSEQUAL, false) => signed_interval(signed_c, i128::MAX / 2, bits),
        _ => return None,
    };
    let set = if truth { set } else { complement(&set, bits) };
    Some(Literal {
        key: key.clone(),
        bits,
        set,
    })
}

// ---------------------------------------------------------------------------
// Facts.

/// What is known at one program point: conditions that hold, as literals on
/// compared expressions or as raw boolean expressions.
#[derive(Clone, Debug, Default)]
pub struct Facts {
    literals: Vec<Literal>,
    raw: Vec<(Expr, bool)>,
}

impl Facts {
    /// `expr == truth` holds here.
    pub fn assume(&mut self, expr: &Expr, truth: bool) {
        match expr {
            Expr::Op {
                code: code::BOOL_NEGATE,
                args,
            } if args.len() == 1 => self.assume(&args[0], !truth),
            Expr::Op {
                code: code::BOOL_AND,
                args,
            } if args.len() == 2 && truth => {
                self.assume(&args[0], true);
                self.assume(&args[1], true);
            }
            Expr::Op {
                code: code::BOOL_OR,
                args,
            } if args.len() == 2 && !truth => {
                self.assume(&args[0], false);
                self.assume(&args[1], false);
            }
            Expr::Op { code, args } if args.len() == 2 => {
                if let Some(literal) = literal(*code, &args[0], &args[1], truth) {
                    self.literals.push(literal);
                }
                self.raw.push((expr.clone(), truth));
            }
            _ => {
                if complete(expr) {
                    self.raw.push((expr.clone(), truth));
                }
            }
        }
    }

    /// `effect` has run: `variable = constant` makes the variable's value
    /// known (after [`Facts::kill`] dropped what it overwrote).
    pub fn assign(&mut self, effect: &Effect) {
        let (Some(out @ Expr::Var { .. }), [value @ Expr::Const { .. }]) =
            (effect.out.as_ref(), effect.args.as_slice())
        else {
            return;
        };
        if effect.code == code::COPY {
            self.assume(&Expr::Op {
                code: code::INT_EQUAL,
                args: vec![out.clone(), value.clone()],
            }, true);
        }
    }

    /// Drops the facts `effect` may invalidate.
    pub fn kill(&mut self, effect: &Effect) {
        let stale = |expr: &Expr| {
            let mut found = Reads::default();
            reads(expr, &mut found);
            clobbers(effect, &found)
        };
        self.literals.retain(|literal| !stale(&literal.key));
        self.raw.retain(|(expr, _)| !stale(expr));
    }

    /// The value `expr` is known to have: `Some(true)` / `Some(false)` when
    /// the facts decide it.
    pub fn value(&self, expr: &Expr) -> Option<bool> {
        match expr {
            Expr::Op {
                code: code::BOOL_NEGATE,
                args,
            } if args.len() == 1 => self.value(&args[0]).map(|known| !known),
            Expr::Op {
                code: code::BOOL_AND,
                args,
            } if args.len() == 2 => match (self.value(&args[0]), self.value(&args[1])) {
                (Some(false), _) | (_, Some(false)) => Some(false),
                (Some(true), Some(true)) => Some(true),
                _ => None,
            },
            Expr::Op {
                code: code::BOOL_OR,
                args,
            } if args.len() == 2 => match (self.value(&args[0]), self.value(&args[1])) {
                (Some(true), _) | (_, Some(true)) => Some(true),
                (Some(false), Some(false)) => Some(false),
                _ => None,
            },
            _ => self.compared(expr),
        }
    }

    fn compared(&self, expr: &Expr) -> Option<bool> {
        if let Some((_, truth)) = self.raw.iter().find(|(fact, _)| same(fact, expr)) {
            return Some(*truth);
        }
        let Expr::Op { code, args } = expr else {
            return None;
        };
        if args.len() != 2 {
            return None;
        }
        let asked = literal(*code, &args[0], &args[1], true)?;
        // Everything known about the compared expression.
        let mut known: Option<Set> = None;
        for fact in self.literals.iter().filter(|fact| same(&fact.key, &asked.key)) {
            if fact.bits != asked.bits {
                continue;
            }
            known = Some(match known {
                None => fact.set.clone(),
                Some(set) => intersect(&set, &fact.set),
            });
        }
        let known = known?;
        if subset(&known, &asked.set) {
            Some(true)
        } else if intersect(&known, &asked.set).is_empty() {
            Some(false)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn var(high: u32, ssa: u64) -> Expr {
        Expr::Var {
            size: 4,
            ssa,
            high,
            storage: Storage {
                class: 0,
                aliased: false,
            },
        }
    }

    fn constant(value: u64) -> Expr {
        Expr::Const { size: 4, value }
    }

    fn cmp(code: u32, a: Expr, b: Expr) -> Expr {
        Expr::Op {
            code,
            args: vec![a, b],
        }
    }

    #[test]
    fn same_ignores_the_ssa_version_of_one_variable() {
        assert!(same(&var(3, 10), &var(3, 99)));
        assert!(!same(&var(3, 10), &var(4, 10)));
        assert!(!same(&Expr::Opaque, &Expr::Opaque));
    }

    #[test]
    fn a_failed_test_decides_its_negation_and_its_wider_neighbours() {
        let mut facts = Facts::default();
        facts.assume(&cmp(code::INT_EQUAL, var(1, 1), constant(0)), true);
        assert_eq!(
            facts.value(&cmp(code::INT_NOTEQUAL, var(1, 7), constant(0))),
            Some(false)
        );
        assert_eq!(
            facts.value(&cmp(code::INT_LESS, var(1, 7), constant(2))),
            Some(true)
        );
        assert_eq!(
            facts.value(&cmp(code::INT_EQUAL, var(1, 7), constant(1))),
            Some(false)
        );
        assert_eq!(facts.value(&cmp(code::INT_EQUAL, var(2, 7), constant(1))), None);
    }

    #[test]
    fn signed_and_unsigned_ranges_agree_on_equality() {
        let mut facts = Facts::default();
        // x s< 2 and x != 1 leaves the negatives and 0.
        facts.assume(&cmp(code::INT_SLESS, var(1, 1), constant(2)), true);
        facts.assume(&cmp(code::INT_EQUAL, var(1, 1), constant(1)), false);
        assert_eq!(facts.value(&cmp(code::INT_EQUAL, var(1, 1), constant(2))), Some(false));
        assert_eq!(facts.value(&cmp(code::INT_EQUAL, var(1, 1), constant(0))), None);
        facts.assume(&cmp(code::INT_EQUAL, var(1, 1), constant(0)), false);
        assert_eq!(
            facts.value(&cmp(code::INT_SLESS, var(1, 1), constant(0))),
            Some(true),
            "only the negatives are left"
        );
    }

    #[test]
    fn a_boolean_or_that_failed_decides_both_operands() {
        let a = cmp(code::INT_NOTEQUAL, var(1, 1), constant(0));
        let b = cmp(code::INT_NOTEQUAL, var(2, 2), constant(0));
        let either = Expr::Op {
            code: code::BOOL_OR,
            args: vec![a.clone(), b.clone()],
        };
        let mut facts = Facts::default();
        facts.assume(&either, false);
        assert_eq!(facts.value(&a), Some(false));
        assert_eq!(facts.value(&b), Some(false));
        assert_eq!(
            facts.value(&cmp(code::INT_EQUAL, var(2, 9), constant(0))),
            Some(true)
        );
    }

    #[test]
    fn a_call_kills_aliased_facts_only() {
        let aliased = Expr::Var {
            size: 4,
            ssa: 5,
            high: 8,
            storage: Storage {
                class: 2,
                aliased: true,
            },
        };
        let mut facts = Facts::default();
        facts.assume(&cmp(code::INT_EQUAL, aliased.clone(), constant(0)), true);
        facts.assume(&cmp(code::INT_EQUAL, var(1, 1), constant(0)), true);
        facts.kill(&Effect {
            calls: true,
            ..Effect::default()
        });
        assert_eq!(facts.value(&cmp(code::INT_EQUAL, aliased, constant(0))), None);
        assert_eq!(
            facts.value(&cmp(code::INT_EQUAL, var(1, 1), constant(0))),
            Some(true)
        );
        facts.kill(&Effect {
            out: Some(var(1, 2)),
            ..Effect::default()
        });
        assert_eq!(
            facts.value(&cmp(code::INT_EQUAL, var(1, 1), constant(0))),
            None
        );
    }
}
