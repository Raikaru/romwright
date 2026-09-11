//! BSim-style semantic feature vectors over p-code data-flow.
//!
//! Ghidra's BSim matches functions by hashing normalised p-code features
//! of a function's data-flow, so two builds of the same source match even
//! when the instruction encodings differ. This module is that idea over
//! the p-code the console already produces (`ConsoleSession::pcode_batch`):
//! a per-function feature multiset, a fixed-size signature hashed from
//! it, and a similarity in [0,1].
//!
//! What is normalised away, and why:
//!
//! * Register, unique-temporary, stack and RAM offsets are dropped; only
//!   the operand *kind* (constant, register, unique, RAM, stack) and the
//!   varnode size are kept. A rebuild reallocates registers and reloads
//!   at different addresses, but the computation reads the same kinds of
//!   values in the same widths.
//! * Opcodes are kept verbatim. They are the translator's own canonical
//!   names (`INT_ADD`, `CBRANCH`, ...), already free of encoding detail.
//! * Constants equal to an address move between builds, so a constant is
//!   kept by value only when it is small (`<= SMALL_CONST_MAX`); anything
//!   larger becomes an opaque `C` (big/address-like). Measured on the
//!   x86-64 `plain_o0`/`plain_o2` corpus pair: keeping small constants
//!   separates true pairs from false ones better than dropping every
//!   constant does (true-pair similarities stay where they were while
//!   false-pair similarities fall), because small immediates -- zeroing,
//!   structure offsets, small masks -- are part of the computation while
//!   linked addresses are not. The numbers are in the gate report
//!   (`benchmarks/reports/m18-001.json`); the policy constant records the
//!   choice, not the proof.
//! * Data-flow context is kept to depth two: for each operation, the
//!   opcodes of the operations producing its inputs, and their producers
//!   in turn. Depth one is what survives optimisation (an optimiser
//!   rewrites chains); depth two is kept because it costs nothing and
//!   only sharpens the vector. Deeper context would couple the signature
//!   to scheduling choices a rebuild freely remakes.
//!
//! Producer tracking is last-writer-wins in emission order over
//! `(space, offset)` keys, ignoring size so a partial register write
//! still links to the full register's producer. That is a simplification
//! of real def-use chains -- memory aliasing through RAM is not modelled
//! at all -- which is why this is one evidence class beside the
//! structural ones, never a verdict on its own.
//!
//! Determinism: feature strings are hashed with FNV-1a over a fixed
//! offset basis (no process seed anywhere), features are visited in
//! emission order, and every output is sorted where order could vary, so
//! the same operations always give the same bytes.

/// Feature-vector width. 256 buckets of 32-bit counters: a 1 KiB
/// signature, small enough to store per function, wide enough that two
/// unrelated bodies rarely share every bucket they touch.
pub const DIM: usize = 256;

/// A constant is kept by value only at or below this. Linked addresses in
/// the corpus sit at 0x100000 and up while computational immediates sit
/// below a page; 0xfff keeps the latter and abstracts the former.
pub const SMALL_CONST_MAX: u64 = 0xfff;

/// Minimum similarity for the matcher to treat a pair as semantic
/// evidence outright (`Evidence::Semantic`), and the gate for the
/// semantic term in `content_score`: below this the structural score is
/// left untouched. Mutual-best is required as well, so this floor guards
/// precision, not recall. Measured: identical data-flow across builds
/// scores 1.0; a genuinely restructured pair (`add`: eight frame-setup
/// instructions optimised to `lea; ret`) scores 0.54; true O0/O2 pairs on
/// a 400-function corpus sit at median 0.56 with siblings that differ by
/// one constant scoring higher (0.63), so no floor can separate those --
/// the class abstains there and must not dilute, which is what the gate
/// on the term is for.
pub const MATCH_FLOOR: f64 = 0.90;

/// Weight of the semantic term inside `content_score`, beside the
/// structural terms. It only ever joins the mean for similarities at or
/// above the floor, so it lifts near-floor structural pairs with
/// identical data-flow and can never sink anything.
pub const SCORE_WEIGHT: f64 = 0.5;

/// One p-code operand as the console prints it: `<space>:<offset>:<size>`.
/// `lre-core` builds these from `PcodeVarnode` (this crate must not
/// depend on `lre-core`: the dependency runs the other way); tests build
/// them by hand.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemVar {
    pub space: String,
    pub offset: u64,
    pub size: u32,
}

/// One p-code operation: the translator's opcode name, its optional
/// output, and its inputs in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemOp {
    pub opcode: String,
    pub output: Option<SemVar>,
    pub inputs: Vec<SemVar>,
}

impl SemOp {
    /// Shorthand for tests: an operation over `(space, offset, size)`
    /// triples, with no output.
    pub fn plain(opcode: &str, inputs: &[(&str, u64, u32)]) -> Self {
        Self {
            opcode: opcode.to_string(),
            output: None,
            inputs: inputs
                .iter()
                .map(|(space, offset, size)| SemVar {
                    space: space.to_string(),
                    offset: *offset,
                    size: *size,
                })
                .collect(),
        }
    }
}

/// The operand kind a feature keeps: what the value is, never which
/// numbered register or linked address it is.
fn kind(var: &SemVar) -> String {
    match var.space.as_str() {
        "const" if var.offset <= SMALL_CONST_MAX => format!("c{}", var.offset),
        "const" => "C".to_string(),
        "register" => format!("r{}", var.size),
        "unique" => format!("u{}", var.size),
        "ram" => format!("m{}", var.size),
        "stack" => format!("s{}", var.size),
        other => format!("{other}{}", var.size),
    }
}

/// The feature multiset of one function body, in emission order: the
/// opcode, the full operand-kind shape, and the producing opcodes of
/// each input to depth two.
pub fn features(ops: &[SemOp]) -> Vec<String> {
    // Last writer of each value, so an input links to the opcode that
    // produced it, plus that producer's own producer for depth two.
    // Keyed by (space, offset) without size: a partial register write
    // still belongs to that register's chain.
    let mut producer: std::collections::HashMap<(String, u64), String> =
        std::collections::HashMap::new();
    let mut grand: std::collections::HashMap<(String, u64), String> =
        std::collections::HashMap::new();
    let mut out = Vec::new();
    for op in ops {
        out.push(format!("o:{}", op.opcode));
        let shape = format!(
            "s:{}|{}|{}",
            op.opcode,
            op.inputs
                .iter()
                .map(kind)
                .collect::<Vec<_>>()
                .join(","),
            op.output.as_ref().map(kind).unwrap_or_else(|| "-".to_string())
        );
        out.push(shape);
        // The chain this operation extends: its first data input's
        // producer becomes the grand-producer of whatever it writes.
        let mut own_grand: Option<String> = None;
        for input in &op.inputs {
            if input.space == "const" {
                continue;
            }
            let key = (input.space.clone(), input.offset);
            if let Some(first) = producer.get(&key).cloned() {
                out.push(format!("d1:{}<<{}", op.opcode, first));
                if own_grand.is_none() {
                    own_grand = Some(first.clone());
                }
                if let Some(second) = grand.get(&key).cloned() {
                    out.push(format!("d2:{}<<{}<<{}", op.opcode, first, second));
                }
            }
        }
        if let Some(written) = &op.output {
            let key = (written.space.clone(), written.offset);
            producer.insert(key.clone(), op.opcode.clone());
            match own_grand {
                Some(chain) => {
                    grand.insert(key, chain);
                }
                None => {
                    grand.remove(&key);
                }
            }
        }
    }
    out
}

/// Fixed-size signature: weighted feature counts hashed into `DIM`
/// buckets with FNV-1a over a constant seed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub buckets: [u32; DIM],
    /// How many feature strings were hashed. Zero means no evidence, and
    /// `similarity` refuses to score it rather than compare emptiness.
    pub features: u32,
}

impl Signature {
    /// Empty signature: no operations, no evidence.
    pub fn empty() -> Self {
        Self {
            buckets: [0; DIM],
            features: 0,
        }
    }

    /// Hex of the buckets little-endian, the store form.
    pub fn to_hex(&self) -> String {
        let mut text = String::with_capacity(DIM * 8);
        for bucket in &self.buckets {
            text.push_str(&format!("{bucket:08x}"));
        }
        text
    }

    /// Parses `to_hex` output; anything else is not a signature.
    pub fn parse_hex(text: &str) -> Option<Self> {
        if text.len() != DIM * 8 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let mut buckets = [0u32; DIM];
        for (index, slot) in buckets.iter_mut().enumerate() {
            *slot = u32::from_str_radix(&text[index * 8..index * 8 + 8], 16).ok()?;
        }
        let features = buckets.iter().sum();
        Some(Self { buckets, features })
    }

    /// Cosine similarity in [0,1], or `None` when either side holds no
    /// evidence. Buckets are non-negative, so the cosine cannot leave
    /// the unit interval; the clamp only absorbs float rounding.
    pub fn similarity(&self, other: &Self) -> Option<f64> {
        if self.features == 0 || other.features == 0 {
            return None;
        }
        let mut dot: u64 = 0;
        let mut left: u64 = 0;
        let mut right: u64 = 0;
        for index in 0..DIM {
            let (a, b) = (u64::from(self.buckets[index]), u64::from(other.buckets[index]));
            dot += a * b;
            left += a * a;
            right += b * b;
        }
        if left == 0 || right == 0 {
            return None;
        }
        let value = dot as f64 / ((left as f64).sqrt() * (right as f64).sqrt());
        Some(value.clamp(0.0, 1.0))
    }
}

fn fnv1a(text: &str) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in text.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// Hashes a body's operations into its signature. Same operations, same
/// bytes, every run: the hash seed is a constant and features are
/// visited in emission order.
pub fn signature(ops: &[SemOp]) -> Signature {
    let mut buckets = [0u32; DIM];
    let mut count: u32 = 0;
    for feature in features(ops) {
        let index = (fnv1a(&feature) % DIM as u64) as usize;
        buckets[index] = buckets[index].saturating_add(1);
        count = count.saturating_add(1);
    }
    Signature {
        buckets,
        features: count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn var(space: &str, offset: u64, size: u32) -> SemVar {
        SemVar {
            space: space.to_string(),
            offset,
            size,
        }
    }

    fn op(opcode: &str, output: Option<SemVar>, inputs: Vec<SemVar>) -> SemOp {
        SemOp {
            opcode: opcode.to_string(),
            output,
            inputs,
        }
    }

    /// The same computation under two register allocations: every input
    /// and output moved to a different register, widths unchanged.
    fn computation(registers: &[u64]) -> Vec<SemOp> {
        let r = |index: usize| var("register", registers[index], 8);
        let u = |index: u64| var("unique", index, 8);
        vec![
            op("COPY", Some(u(0x1000)), vec![r(0)]),
            op(
                "INT_ADD",
                Some(u(0x1020)),
                vec![u(0x1000), var("const", 16, 8)],
            ),
            op("INT_MULT", Some(u(0x1040)), vec![u(0x1020), r(1)]),
            op("STORE", None, vec![var("ram", 0x401000, 8), u(0x1040)]),
        ]
    }

    #[test]
    fn same_computation_different_registers_shares_every_feature() {
        let left = computation(&[0x10, 0x11]);
        let right = computation(&[0x28, 0x2f]);
        assert_eq!(features(&left), features(&right));
        let similarity = signature(&left).similarity(&signature(&right));
        assert!(
            matches!(similarity, Some(value) if value > 0.99),
            "same computation must score high, got {similarity:?}"
        );
    }

    #[test]
    fn unrelated_computations_score_low() {
        let arithmetic = computation(&[0x10, 0x11]);
        let branchy = vec![
            op(
                "INT_SLESS",
                Some(var("unique", 0x2000, 1)),
                vec![var("register", 0x10, 8), var("const", 0, 8)],
            ),
            op(
                "CBRANCH",
                None,
                vec![var("ram", 0x402000, 8), var("unique", 0x2000, 1)],
            ),
            op("RETURN", None, vec![var("unique", 0x2008, 8)]),
        ];
        let similarity = signature(&arithmetic).similarity(&signature(&branchy));
        assert!(
            matches!(similarity, Some(value) if value < 0.5),
            "unrelated bodies must score low, got {similarity:?}"
        );
    }

    #[test]
    fn signature_is_byte_identical_across_runs() {
        let ops = computation(&[0x10, 0x11]);
        let first = signature(&ops).to_hex();
        let second = signature(&ops).to_hex();
        assert_eq!(first, second);
        assert_eq!(first.len(), DIM * 8);
        let parsed = Signature::parse_hex(&first).expect("own output must parse");
        assert_eq!(parsed.to_hex(), first);
        assert!(Signature::parse_hex("not hex").is_none());
        assert!(Signature::parse_hex(&first[..16]).is_none());
    }

    #[test]
    fn linked_addresses_normalise_away_small_consts_stay() {
        // The same store to two different linked addresses: one feature
        // set, because addresses move between builds.
        let to_first = vec![SemOp::plain("STORE", &[("ram", 0x401000, 8), ("unique", 1, 8)])];
        let to_second = vec![SemOp::plain("STORE", &[("ram", 0x802000, 8), ("unique", 1, 8)])];
        assert_eq!(features(&to_first), features(&to_second));
        // A different small immediate is a different computation.
        let add_16 = vec![SemOp::plain("INT_ADD", &[("unique", 1, 8), ("const", 16, 8)])];
        let add_24 = vec![SemOp::plain("INT_ADD", &[("unique", 1, 8), ("const", 24, 8)])];
        assert_ne!(features(&add_16), features(&add_24));
    }

    #[test]
    fn data_flow_context_separates_rewired_bodies() {
        // Same opcodes, same operand kinds, but the multiply reads the
        // loaded value in one body and the added value in the other.
        let through_add = vec![
            op(
                "INT_ADD",
                Some(var("unique", 1, 8)),
                vec![var("unique", 0, 8), var("const", 1, 8)],
            ),
            op(
                "INT_MULT",
                Some(var("unique", 2, 8)),
                vec![var("unique", 1, 8), var("unique", 0, 8)],
            ),
        ];
        let through_load = vec![
            op(
                "INT_ADD",
                Some(var("unique", 1, 8)),
                vec![var("unique", 3, 8), var("const", 1, 8)],
            ),
            op(
                "INT_MULT",
                Some(var("unique", 2, 8)),
                vec![var("unique", 0, 8), var("unique", 0, 8)],
            ),
        ];
        let similarity = signature(&through_add).similarity(&signature(&through_load));
        assert!(
            matches!(similarity, Some(value) if value < 1.0),
            "rewired data-flow must not be identical, got {similarity:?}"
        );
    }

    #[test]
    fn empty_signatures_carry_no_evidence() {
        assert_eq!(Signature::empty().similarity(&Signature::empty()), None);
        let ops = computation(&[0x10, 0x11]);
        assert_eq!(Signature::empty().similarity(&signature(&ops)), None);
    }
}
