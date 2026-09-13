//! Matching byte windows against a loaded signature database.
//!
//! The index is built once per pass and keyed by the first compared byte of a
//! pattern, so a window only compares against records that can possibly match.
//! Two records claiming different names for one window are a conflict and name
//! nothing: a wrong name is worse than no name.
use crate::{Signature, SignatureDb};
use std::collections::{BTreeSet, HashMap};

/// What the index concluded about one window.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome<'a> {
    /// No record matched.
    Unmatched,
    /// Exactly one name matched; the record carries the strongest evidence.
    Named(&'a Signature),
    /// Several records matched with different names.
    Conflict { names: Vec<String> },
}

/// Records grouped by language and by the first byte they compare.
#[derive(Debug, Default)]
pub struct MatchIndex<'a> {
    buckets: HashMap<(&'a str, usize, u8), Vec<&'a Signature>>,
    /// Distinct first-compared offsets per language, ascending.
    offsets: HashMap<&'a str, BTreeSet<usize>>,
}

impl<'a> MatchIndex<'a> {
    pub fn build(databases: impl IntoIterator<Item = &'a SignatureDb>) -> Self {
        let mut index = Self::default();
        for database in databases {
            for signature in database.signatures() {
                let Some(first) = signature.mask.iter().position(|&keep| keep != 0) else {
                    continue;
                };
                index
                    .buckets
                    .entry((&signature.language, first, signature.pattern[first]))
                    .or_default()
                    .push(signature);
                index
                    .offsets
                    .entry(&signature.language)
                    .or_default()
                    .insert(first);
            }
        }
        index
    }

    pub fn records(&self) -> usize {
        self.buckets.values().map(Vec::len).sum()
    }

    /// Matches `window`, which must start at the function's entry.
    ///
    /// `body` is the function's own proven size; a record shorter than the body
    /// would name a function after a fragment of itself, so it is ignored.
    pub fn lookup(&self, language: &str, window: &[u8], body: usize) -> Outcome<'a> {
        let Some(offsets) = self.offsets.get(language) else {
            return Outcome::Unmatched;
        };
        let mut best: Option<&'a Signature> = None;
        let mut names = BTreeSet::new();
        for &offset in offsets {
            let Some(&byte) = window.get(offset) else {
                break;
            };
            let Some(bucket) = self.buckets.get(&(language, offset, byte)) else {
                continue;
            };
            for &signature in bucket {
                if signature.pattern.len() < body || !signature.matches(window) {
                    continue;
                }
                names.insert(signature.name.clone());
                if best.is_none_or(|current| {
                    signature.compared_bytes() > current.compared_bytes()
                }) {
                    best = Some(signature);
                }
            }
        }
        match (names.len(), best) {
            (0, _) | (_, None) => Outcome::Unmatched,
            (1, Some(signature)) => Outcome::Named(signature),
            (_, Some(_)) => Outcome::Conflict {
                names: names.into_iter().collect(),
            },
        }
    }
}

/// Share of the record's bytes that were actually compared: the evidence a
/// match rests on, in [0, 1].
pub fn confidence(signature: &Signature) -> f64 {
    signature.compared_bytes() as f64 / signature.pattern.len() as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signature(name: &str, package: &str, pattern: &[u8], mask: &[u8]) -> Signature {
        Signature::new("x86:LE:64:default", name, package, "MIT", pattern, mask).unwrap()
    }

    fn database(signatures: Vec<Signature>) -> SignatureDb {
        SignatureDb::from_signatures(signatures).unwrap()
    }

    #[test]
    fn one_name_wins_across_databases_and_two_names_cancel() {
        let prologue = [0x55, 0x48, 0x89, 0xe5, 0xde, 0xad, 0xbe, 0xef];
        let masked_mask = [0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0];
        let masked = signature("strlen", "p-1", &prologue, &masked_mask);
        let twin = signature("strnlen", "p-1", &prologue, &masked_mask);
        let window = [0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x5d, 0xc3];
        let alias = signature("strlen", "p-2", &window, &[0xff; 8]);
        let weak = database(vec![masked.clone()]);
        let exact = database(vec![alias]);
        let index = MatchIndex::build([&weak, &exact]);
        assert_eq!(index.records(), 2);
        match index.lookup("x86:LE:64:default", &window, 8) {
            // Both databases claim `strlen`; the fully compared record is the
            // stronger evidence and wins.
            Outcome::Named(found) => {
                assert_eq!((found.name.as_str(), found.package.as_str()), ("strlen", "p-2"));
                assert_eq!(found.compared_bytes(), 8);
                assert_eq!(confidence(found), 1.0);
                assert_eq!(confidence(&masked), 0.5);
            }
            other => panic!("{other:?}"),
        }
        let conflicting = database(vec![masked, twin]);
        let index = MatchIndex::build([&conflicting]);
        assert_eq!(
            index.lookup("x86:LE:64:default", &window, 8),
            Outcome::Conflict {
                names: vec!["strlen".into(), "strnlen".into()]
            }
        );
    }

    #[test]
    fn language_body_size_and_window_length_all_gate_a_match() {
        let owner = database(vec![signature("memcpy", "p-1", &[0x90; 24], &[0xff; 24])]);
        let index = MatchIndex::build([&owner]);
        let window = [0x90u8; 24];
        assert!(matches!(
            index.lookup("x86:LE:64:default", &window, 24),
            Outcome::Named(_)
        ));
        assert_eq!(
            index.lookup("AARCH64:LE:64:v8A", &window, 24),
            Outcome::Unmatched,
            "a record never matches another language's bytes"
        );
        assert_eq!(
            index.lookup("x86:LE:64:default", &window, 40),
            Outcome::Unmatched,
            "a record shorter than the proven body names a fragment"
        );
        assert_eq!(
            index.lookup("x86:LE:64:default", &window[..8], 8),
            Outcome::Unmatched,
            "a short window cannot satisfy the pattern"
        );
        assert_eq!(
            index.lookup("x86:LE:64:default", &[0x91; 24], 24),
            Outcome::Unmatched
        );
    }
}
