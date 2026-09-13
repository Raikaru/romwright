//! A stricter spec compiler: validation passes over a Ghidra language tree
//! that error on the defect classes Ghidra's own `sleigh` only warns about.
//!
//! The motivation is concrete — every failure these checks name was observed
//! shipping a spec bundle:
//!
//! - **Unknown opinion attribute.** `QueryOpinionServiceHandler` reads only
//!   `loader`; a module that writes `load=` (GhidraSPU did) is silently
//!   ignored, so the language never answers for its machine. This lints the
//!   attribute set, not just the one Ghidra happens to read.
//! - **Missing compiled spec.** An `.ldefs` `<language slafile="…">` that
//!   names a `.sla` that was never built (65802) is a language that cannot
//!   decode. Ghidra reports it only as "Language not found" at import time.
//! - **Disabled language.** A `<language>` element commented out in the
//!   `.ldefs` (CR16AB) is invisible to discovery — surfaced here so a missing
//!   language is a finding, not a silent gap.
//! - **cspec schema drift.** `segmentop` without a `<pcode>` body is the
//!   pre-12.x form; the current parser rejects it. `callotherfixup` without
//!   `targetop` is meaningless.
//!
//! Each finding carries the file and the rule; `Error` severity means the
//! language cannot produce a correct spec bundle.

use std::path::{Path, PathBuf};

/// One lint finding.
#[derive(Debug, Clone)]
pub struct Finding {
    /// The file the finding names.
    pub path: PathBuf,
    /// `error` blocks a trustworthy bundle; `warn` is suspicious but legal.
    pub severity: Severity,
    /// The rule that fired, e.g. `opinion.unknown-attribute`.
    pub rule: &'static str,
    /// What was found and why it matters.
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warn,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Severity::Error => "error",
            Severity::Warn => "warn",
        })
    }
}

/// `name="value"` pairs of one tag, in order.
fn attrs(tag: &str) -> Vec<(String, String)> {
    let bytes = tag.as_bytes();
    let named = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'_' | b':' | b'-' | b'/');
    let mut pairs = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && !named(bytes[i]) {
            i += 1;
        }
        let start = i;
        while i < bytes.len() && named(bytes[i]) {
            i += 1;
        }
        if i == start {
            break;
        }
        let name = &tag[start..i];
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i < bytes.len() && bytes[i] == b'=' {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < bytes.len() && bytes[i] == b'"' {
                let vstart = i + 1;
                let mut j = vstart;
                while j < bytes.len() && bytes[j] != b'"' {
                    j += 1;
                }
                pairs.push((name.to_string(), tag[vstart..j].to_string()));
                i = j + 1;
            }
        }
    }
    pairs
}

/// Every `<name …>` open-tag's attribute list, in document order.
fn tags_named<'a>(xml: &'a str, name: &str) -> Vec<(&'a str, Vec<(String, String)>)> {
    let mut out = Vec::new();
    let needle = format!("<{name}");
    let mut rest = xml;
    while let Some(p) = rest.find(&needle) {
        let tag = &rest[p..];
        let Some(end) = tag.find('>') else { break };
        let inner = &tag[1..end];
        out.push((inner, attrs(inner)));
        rest = &tag[end..];
    }
    out
}

fn get<'a>(pairs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// The attribute names a `<constraint>` may carry (QueryOpinionServiceHandler).
const CONSTRAINT_ATTRS: &[&str] = &[
    "loader",
    "primary",
    "secondary",
    "processor",
    "endian",
    "size",
    "variant",
    "compilerSpecID",
];

/// Lint one `.opinion` file: every `<constraint>` attribute must be one the
/// opinion service actually reads.
fn lint_opinion(path: &Path, xml: &str, out: &mut Vec<Finding>) {
    for (_, pairs) in tags_named(xml, "constraint") {
        for (name, _) in &pairs {
            if !CONSTRAINT_ATTRS.contains(&name.as_str()) {
                out.push(Finding {
                    path: path.to_path_buf(),
                    severity: Severity::Error,
                    rule: "opinion.unknown-attribute",
                    message: format!(
                        "constraint attribute `{name}` is not one the opinion service reads \
                         (loader/primary/secondary/processor/endian/size/variant/compilerSpecID); \
                         a `load=` typo here silently disables the language"
                    ),
                });
            }
        }
    }
}

/// Lint one `.ldefs` file: each `<language>`'s slafile, processorspec, and
/// compiler spec files must exist beside it. A `<language>` element that is
/// commented out is reported so a disabled language is a finding, not a gap.
fn lint_ldefs(path: &Path, xml: &str, out: &mut Vec<Finding>) {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    // Strip comments for the live-language pass, but remember which ids were
    // commented out so we can report them as disabled.
    let mut commented_ids = Vec::new();
    let mut rest = xml;
    let mut live = String::new();
    while let Some(c) = rest.find("<!--") {
        live.push_str(&rest[..c]);
        let seg = &rest[c..];
        let Some(e) = seg.find("-->") else { break };
        let comment = &seg[..e];
        for (_, pairs) in tags_named(comment, "language") {
            if let Some(id) = get(&pairs, "id") {
                commented_ids.push(id.to_string());
            }
        }
        rest = &seg[e + 3..];
    }
    live.push_str(rest);
    for id in commented_ids {
        out.push(Finding {
            path: path.to_path_buf(),
            severity: Severity::Warn,
            rule: "ldefs.disabled-language",
            message: format!("language {id} is commented out in the ldefs — disabled upstream"),
        });
    }
    for (_, pairs) in tags_named(&live, "language") {
        let Some(id) = get(&pairs, "id") else { continue };
        if let Some(sla) = get(&pairs, "slafile") {
            if !dir.join(sla).is_file() {
                out.push(Finding {
                    path: path.to_path_buf(),
                    severity: Severity::Error,
                    rule: "ldefs.missing-sla",
                    message: format!(
                        "language {id} names slafile `{sla}` but {sla} is not built in {}",
                        dir.display()
                    ),
                });
            }
        }
        if let Some(pspec) = get(&pairs, "processorspec") {
            if !dir.join(pspec).is_file() {
                out.push(Finding {
                    path: path.to_path_buf(),
                    severity: Severity::Error,
                    rule: "ldefs.missing-pspec",
                    message: format!("language {id} names processorspec `{pspec}` that is absent"),
                });
            }
        }
    }
    for (_, pairs) in tags_named(&live, "compiler") {
        if let Some(spec) = get(&pairs, "spec") {
            if !dir.join(spec).is_file() {
                out.push(Finding {
                    path: path.to_path_buf(),
                    severity: Severity::Error,
                    rule: "ldefs.missing-cspec",
                    message: format!("compiler spec `{spec}` is absent from {}", dir.display()),
                });
            }
        }
    }
}

/// Count instruction constructors in one `.sinc`/`.slaspec` body: a line
/// whose first non-space char is `:`. In SLEIGH every table production —
/// mnemonic or operand subtable — opens with `:`; the `is`/`{` may follow on
/// later lines, so the `:` alone is the reliable signal. A stub has none.
fn count_constructors(text: &str) -> usize {
    text.lines()
        .filter(|l| l.trim_start().starts_with(':'))
        .count()
}

/// Resolve a `.slaspec`'s `@include` tree (relative to its dir) and count
/// total constructors. A language whose whole spec tree yields zero is a
/// stub that compiles to a `.sla` decoding nothing.
fn lint_slaspec(path: &Path, text: &str, out: &mut Vec<Finding>) {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut total = count_constructors(text);
    let mut seen = std::collections::HashSet::new();
    let mut queue = vec![text.to_string()];
    while let Some(body) = queue.pop() {
        for inc in body.lines().filter_map(|l| {
            let t = l.trim();
            t.strip_prefix("@include")
                .and_then(|r| r.trim().strip_prefix('"'))
                .and_then(|r| r.strip_suffix('"'))
                .map(|s| s.to_string())
        }) {
            let p = dir.join(&inc);
            if !seen.insert(p.clone()) {
                continue;
            }
            if let Ok(t) = std::fs::read_to_string(&p) {
                total += count_constructors(&t);
                queue.push(t);
            }
        }
    }
    if total == 0 {
        out.push(Finding {
            path: path.to_path_buf(),
            severity: Severity::Error,
            rule: "slaspec.stub",
            message: format!(
                "{} resolves to 0 instruction constructors across its include tree — a stub language",
                path.file_name().unwrap_or_default().to_string_lossy()
            ),
        });
    }
}

/// Lint one `.cspec`: schema checks for the elements whose drift we hit.
fn lint_cspec(path: &Path, xml: &str, out: &mut Vec<Finding>) {
    // segmentop must carry a <pcode> body (the current schema); the old
    // attribute form (basesize/innerinsize/baseop/innerop) is rejected.
    for (inner, _) in tags_named(xml, "segmentop") {
        let _ = inner;
        if let Some(start) = xml.find("<segmentop") {
            let seg = &xml[start..];
            let has_pcode = seg
                .find("</segmentop>")
                .map(|e| seg[..e].contains("<pcode"))
                .unwrap_or(false);
            if !has_pcode {
                out.push(Finding {
                    path: path.to_path_buf(),
                    severity: Severity::Error,
                    rule: "cspec.segmentop-no-pcode",
                    message: "segmentop uses the removed attribute form \
                              (basesize/innerinsize/baseop/innerop); the current schema \
                              requires an explicit <pcode> body"
                        .into(),
                });
            }
        }
    }
    for (_, pairs) in tags_named(xml, "callotherfixup") {
        if get(&pairs, "targetop").is_none() {
            out.push(Finding {
                path: path.to_path_buf(),
                severity: Severity::Error,
                rule: "cspec.callotherfixup-no-target",
                message: "callotherfixup has no targetop attribute".into(),
            });
        }
    }
}

/// Lint every language module under `install/Ghidra`, returning all findings.
pub fn lint_install(install: &Path) -> Vec<Finding> {
    let mut out = Vec::new();
    let root = install.join("Ghidra");
    if !root.is_dir() {
        return out;
    }
    let mut dirs = Vec::new();
    collect_language_dirs(&root, &mut dirs);
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let p = entry.path();
            let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
            let Ok(text) = std::fs::read_to_string(&p) else { continue };
            match ext {
                "opinion" => lint_opinion(&p, &text, &mut out),
                "ldefs" => lint_ldefs(&p, &text, &mut out),
                "slaspec" => lint_slaspec(&p, &text, &mut out),
                "cspec" => lint_cspec(&p, &text, &mut out),
                _ => {}
            }
        }
    }
    out
}

/// Collects every `…/data/languages` directory under `root`.
fn collect_language_dirs(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else { return };
    for entry in entries.flatten() {
        let p = entry.path();
        if !p.is_dir() {
            continue;
        }
        let lang = p.join("data/languages");
        if lang.is_dir() {
            out.push(lang);
        } else {
            collect_language_dirs(&p, out);
        }
    }
}
