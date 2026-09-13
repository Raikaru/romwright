//! The Knowledge DB substrate: a fact is a value plus where it came from
//! and how sure it is, so a user assertion and an inference coexist rather
//! than one overwriting the other.
//!
//! This is the store the architecture's analysis layer writes into:
//! `player.health : float` at confidence 1.0 from the user, and
//! `player+0x38 : Vec3` at 0.72 from layout inference, side by side. The
//! type engines (TRex-style structural recovery, the BinSub subtype solver)
//! produce `Fact<Ty>`; cross-build matching and debug info produce the same
//! shape at higher confidence.

use std::collections::BTreeMap;

/// How sure a fact is. Ordered, so a merge keeps the stronger claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// A guess with no direct evidence — kept so a stronger fact can replace it.
    Speculative,
    /// Propagated through a subtype edge or a copy, not observed directly.
    Inferred,
    /// Observed directly in the binary (a use that commits the location).
    Strong,
    /// Stated by an authority: the user, debug info, or a matched build.
    Certain,
}

/// Where a fact came from — the provenance that decides merge precedence
/// and that answers "which pass produced this?" when output is wrong.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactOrigin {
    /// Asserted by the user.
    User,
    /// From DWARF or another debug format.
    DebugInfo,
    /// Propagated from a matched build (cross-build function matching).
    CrossBuild(u64),
    /// A compiler-idiom or pattern pass.
    Pattern(u32),
    /// The subtype/constraint type engine.
    TypeInference,
    /// Ghidra's own analysis, used as an oracle.
    Ghidra,
}

/// A typed fact: the claim, its confidence, and its provenance.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Fact<T> {
    pub value: T,
    pub confidence: Confidence,
    pub origin: FactOrigin,
}

impl<T> Fact<T> {
    pub fn new(value: T, confidence: Confidence, origin: FactOrigin) -> Self {
        Self { value, confidence, origin }
    }

    /// The stronger of two facts on the same subject: higher confidence
    /// wins; equal confidence keeps `self` (the earlier claim).
    pub fn merge(self, other: Fact<T>) -> Fact<T> {
        if other.confidence > self.confidence {
            other
        } else {
            self
        }
    }
}

/// A per-subject fact store: subject key -> the strongest fact so far.
/// `K` is whatever names the thing described — a register offset, a
/// `(function, offset)` pair, a global address.
#[derive(Debug, Clone)]
pub struct FactStore<K, T> {
    facts: BTreeMap<K, Fact<T>>,
}

impl<K, T> Default for FactStore<K, T> {
    fn default() -> Self {
        Self { facts: BTreeMap::new() }
    }
}

impl<K: Ord, T: Clone> FactStore<K, T> {
    /// Record a fact, keeping the stronger claim when the subject already
    /// has one.
    pub fn assert(&mut self, key: K, fact: Fact<T>) {
        self.facts
            .entry(key)
            .and_modify(|existing| {
                if fact.confidence > existing.confidence {
                    *existing = fact.clone();
                }
            })
            .or_insert(fact);
    }


    /// The mutable fact for a subject, so a pass can refine a value in
    /// place — a caller's observed argument type joining into a callee's
    /// inferred signature.
    pub fn get_mut(&mut self, key: &K) -> Option<&mut Fact<T>> {
        self.facts.get_mut(key)
    }
    pub fn get(&self, key: &K) -> Option<&Fact<T>> {
        self.facts.get(key)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&K, &Fact<T>)> {
        self.facts.iter()
    }

    pub fn len(&self) -> usize {
        self.facts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.facts.is_empty()
    }
}
