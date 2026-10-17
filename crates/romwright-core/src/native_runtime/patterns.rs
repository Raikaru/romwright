//! Ghidra `BytePatterns` matching: the function-start patterns the install
//! ships for a language, searched over an image's code bytes.
//!
//! The matcher replaces the console's `functionstarts` command
//! (`IfcFunctionStarts`, once in `native/romwright_patterns.hh`). The pattern
//! files are read as Ghidra's `ghidra.util.bytesearch` classes read them
//! (Apache-2.0, Ghidra 12.1.3; `Features/Base/src/main/java/ghidra/util/bytesearch/`):
//! `DittedBitSequence` (a ditted bit sequence is `0`, `1` and `.` digits, a
//! hex one `0x` bytes whose `.` digits are wildcard nibbles, `*` marks the
//! match offset, `#` comments to the line end), `Pattern` (the match mark
//! and the post rules), `PatternPairSet` (`<patternpairs>` cross every
//! pre-pattern with every post-pattern that fixes enough bits: `totalbits`,
//! `postbits`) and `AlignRule` (`<align mark= bits=>`). Which files a
//! language uses comes from the `patternconstraints.xml` of every
//! `Ghidra/Processors/*/data/patterns` directory, language and compiler
//! conditions nested as `LanguageConstraint`, `CompilerConstraint` and
//! `generic.constraint.DecisionNode` nest them, the more specific decision
//! winning.
//!
//! A match does not create a function: consumers must enforce the ordered
//! action prerequisites against program state.
use super::lift::scan_directory_recursive;
use super::{NativeRuntimeError, Result, SleighLifter};
use kuna_base::address::Address;
use kuna_base::xml::{xml_tree, Element};
use kuna_sleigh::translate::Translate;
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{Arc, LazyLock, Mutex};

/// One pattern rule's action element, as the XML names it.
#[derive(Debug, Clone)]
pub(crate) struct FunctionPatternAction {
    pub kind: String,
    pub attributes: BTreeMap<String, String>,
}

/// The pattern file a rule came from and the actions it carries.
#[derive(Debug)]
pub(crate) struct FunctionPatternRule {
    pub file: String,
    pub actions: Vec<FunctionPatternAction>,
}

#[derive(Debug)]
pub(crate) struct FunctionPatternMatch {
    pub address: u64,
    pub rule: usize,
}

/// The result of one search: the processor's instruction alignment, every
/// rule of the selected pattern files, and the (address, rule) matches.
#[derive(Debug)]
pub(crate) struct FunctionPatterns {
    pub alignment: u64,
    pub rules: Arc<Vec<FunctionPatternRule>>,
    pub matches: Vec<FunctionPatternMatch>,
}

impl FunctionPatterns {
    /// The names the matched `<funcstart validcode="function" label=..>`
    /// rules give their starts, once per (address, label), in match order.
    pub(crate) fn labels(&self) -> Vec<(u64, String)> {
        let mut labels: Vec<(u64, String)> = Vec::new();
        for hit in &self.matches {
            for action in &self.rules[hit.rule].actions {
                if action.kind != "funcstart"
                    || !action
                        .attributes
                        .get("validcode")
                        .is_some_and(|value| value.eq_ignore_ascii_case("function"))
                {
                    continue;
                }
                if let Some(label) = action.attributes.get("label")
                    && !labels.iter().any(|(address, name)| *address == hit.address && name == label) {
                        labels.push((hit.address, label.clone()));
                    }
            }
        }
        labels
    }
}

fn error(message: impl Into<String>) -> NativeRuntimeError {
    NativeRuntimeError(message.into())
}

fn attribute(element: &Element, name: &str) -> Option<String> {
    element
        .get_attribute_value(name)
        .ok()
        .map(|value| String::from_utf8_lossy(value).into_owned())
}

fn required(element: &Element, name: &str) -> Result<String> {
    attribute(element, name).ok_or_else(|| error(format!("Missing pattern attribute: {name}")))
}

fn hex_digit(c: u8) -> Result<u32> {
    match c {
        b'0'..=b'9' => Ok(u32::from(c - b'0')),
        b'a'..=b'f' => Ok(u32::from(c - b'a') + 10),
        b'A'..=b'F' => Ok(u32::from(c - b'A') + 10),
        _ => Err(error("Invalid hexadecimal pattern digit")),
    }
}

/// `SpecXmlUtils.decodeInt` on an attribute: `0x` hex, a leading `0` octal,
/// decimal otherwise, with the low 32 bits of the value kept
/// (`BigInteger.intValue`); an absent attribute or `"0"` is 0.
fn integer(element: &Element, name: &str) -> Result<i32> {
    let Some(text) = attribute(element, name) else {
        return Ok(0);
    };
    if text == "0" {
        return Ok(0);
    }
    let text = text.as_bytes();
    let mut position = 0;
    let mut radix = 10u32;
    if text.starts_with(b"0x") {
        position = 2;
        radix = 16;
    } else if text.first() == Some(&b'0') {
        position = 1;
        radix = 8;
    }
    let negative = text.get(position) == Some(&b'-');
    if negative || text.get(position) == Some(&b'+') {
        position += 1;
    }
    let invalid = || error(format!("Invalid pattern integer: {}", String::from_utf8_lossy(text)));
    if position == text.len() {
        return Err(invalid());
    }
    let mut value = 0u32;
    for &c in &text[position..] {
        let digit = hex_digit(c)?;
        if digit >= radix {
            return Err(invalid());
        }
        value = value.wrapping_mul(radix).wrapping_add(digit);
    }
    if negative {
        value = 0u32.wrapping_sub(value);
    }
    Ok(value as i32)
}

fn trimmed(text: &[u8]) -> String {
    String::from_utf8_lossy(text).trim_matches([' ', '\t', '\r', '\n']).to_owned()
}

/// `languageMatches`: colon-separated fields, `*` matching any one field.
fn language_matches(pattern: &str, language: &str) -> bool {
    let mut pattern = pattern.split(':').filter(|field| !field.is_empty());
    let mut language = language.split(':').filter(|field| !field.is_empty());
    loop {
        match (pattern.next(), language.next()) {
            (None, None) => return true,
            (Some(p), Some(l)) => {
                if p != "*" && p != l {
                    return false;
                }
            }
            _ => return false,
        }
    }
}

/// The `patternconstraints.xml` decision tree: language and compiler
/// conditions leading to a `<patternfile>`.
#[derive(Default)]
struct Decision {
    condition: Option<Rc<Element>>,
    file: Option<Rc<Element>>,
    children: Vec<Decision>,
}

fn same_attribute(a: &Element, b: &Element, name: &str) -> bool {
    attribute(a, name) == attribute(b, name)
}

fn load_decisions(node: &mut Decision, element: &Element) -> Result<()> {
    for child in element.get_children() {
        let kind = child.get_name();
        if kind == "patternfile" {
            if node.file.is_some() {
                return Err(error("Duplicate patternfile decision"));
            }
            node.file = Some(Rc::clone(child));
            continue;
        }
        if kind != "language" && kind != "compiler" {
            return Err(error(format!("Unknown pattern constraint: {kind}")));
        }
        if kind == "language" {
            required(child, "id")?;
        } else if attribute(child, "id").is_none() && attribute(child, "name").is_none() {
            return Err(error("Missing compiler constraint"));
        }
        let existing = node.children.iter().position(|other| {
            let condition = other.condition.as_ref().expect("a child has a condition");
            condition.get_name() == kind
                && same_attribute(condition, child, "id")
                && (kind == "language" || same_attribute(condition, child, "name"))
        });
        let index = existing.unwrap_or_else(|| {
            node.children.push(Decision { condition: Some(Rc::clone(child)), ..Decision::default() });
            node.children.len() - 1
        });
        load_decisions(&mut node.children[index], child)?;
    }
    Ok(())
}

fn select_files(node: &Decision, language: &str, compiler: &str, files: &mut Vec<String>) -> Result<bool> {
    if let Some(condition) = &node.condition {
        if condition.get_name() == "language" {
            if !language_matches(&required(condition, "id")?, language) {
                return Ok(false);
            }
        } else {
            if attribute(condition, "id").is_some_and(|id| id != compiler) {
                return Ok(false);
            }
            // CompilerSpec ID is known; Program.getCompiler() producer
            // metadata is not.
            if attribute(condition, "name").is_some() {
                return Err(error("Pattern selection requires compiler producer metadata"));
            }
        }
    }
    let mut found = false;
    for child in &node.children {
        found |= select_files(child, language, compiler, files)?;
    }
    if !found
        && let Some(file) = &node.file {
            files.push(trimmed(file.get_content()));
            found = true;
        }
    Ok(found)
}

#[derive(Clone, Copy)]
struct Byte {
    value: u8,
    mask: u8,
}

#[derive(Default)]
struct Sequence {
    bytes: Vec<Byte>,
    mark: i32,
    fixed: i64,
}

struct Alignment {
    offset: u32,
    mask: u32,
}

struct Rule {
    alignment: Vec<Alignment>,
}

/// A pattern in the bucket of a byte value: the pattern, and a second byte
/// of it to test before anything else of it is read. Most candidates in a
/// bucket differ there, so most are refused from the bucket's own memory.
#[derive(Clone, Copy)]
struct Candidate {
    pattern: u32,
    /// Where that byte is, relative to the byte the bucket is for.
    offset: i32,
    /// The byte's mask and value; a zero mask tests nothing.
    mask: u8,
    value: u8,
}

struct Pattern {
    pre: usize,
    post: usize,
    rule: usize,
    anchor: usize,
    length: usize,
    mark: i32,
}

/// Ghidra's `DittedBitSequence` text: bytes as `0x..` hex with `.` nibble
/// wildcards, or eight-digit `0`/`1`/`.` groups; `*` names the mark.
fn sequence(element: &Element) -> Result<Sequence> {
    if element.get_name() != "data" || !element.get_children().is_empty() {
        return Err(error("Expected pattern data"));
    }
    let mut result = Sequence { mark: -1, ..Sequence::default() };
    let text = element.get_content();
    let mut mode = -1i32;
    let mut i = 0;
    while i < text.len() {
        let mut c = text[i];
        if matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
            mode = -1;
            i += 1;
            continue;
        }
        if c == b'#' {
            match text[i..].iter().position(|&byte| byte == b'\n') {
                Some(offset) => i += offset,
                None => break,
            }
            continue;
        }
        if mode == -1 {
            if c == b'*' {
                if result.bytes.len() > i32::MAX as usize {
                    return Err(error("Pattern mark exceeds native range"));
                }
                result.mark = result.bytes.len() as i32;
                i += 1;
                continue;
            }
            if c == b'0' && text.get(i + 1) == Some(&b'x') {
                mode = 0;
                i += 2;
                continue;
            }
            if c == b'1' || c == b'.' {
                mode = 1;
            } else if c != b'0' {
                return Err(error("Invalid ditted pattern sequence"));
            }
        }
        let width = if mode == 0 { 2 } else { 8 };
        if width > text.len() - i {
            return Err(error("Incomplete pattern byte"));
        }
        let (mut value, mut mask) = (0u32, 0u32);
        for _ in 0..width {
            let shift = if mode == 0 { 4 } else { 1 };
            value <<= shift;
            mask <<= shift;
            c = text[i];
            i += 1;
            if c == b'.' {
                continue;
            }
            if mode != 0 && c != b'0' && c != b'1' {
                return Err(error("Invalid binary pattern digit"));
            }
            value |= if mode == 0 { hex_digit(c)? } else { u32::from(c - b'0') };
            mask |= (1u32 << shift) - 1;
            result.fixed += i64::from(shift);
        }
        result.bytes.push(Byte { value: value as u8, mask: mask as u8 });
    }
    Ok(result)
}

/// One language's pattern files, loaded: what a search runs.
pub(crate) struct PatternSet {
    sequences: Vec<Sequence>,
    rules: Vec<Rule>,
    described: Arc<Vec<FunctionPatternRule>>,
    patterns: Vec<Pattern>,
    /// Candidates by the value of the byte each pattern's anchor is matched at.
    buckets: Vec<Vec<Candidate>>,
    longest: usize,
}

impl PatternSet {
    fn add_sequence(&mut self, element: &Element) -> Result<usize> {
        self.sequences.push(sequence(element)?);
        Ok(self.sequences.len() - 1)
    }

    fn add_rule(&mut self, element: &Element, skip: usize, file: &str) -> Result<usize> {
        let mut rule = Rule { alignment: Vec::new() };
        let mut described = FunctionPatternRule { file: file.to_owned(), actions: Vec::new() };
        for child in element.get_children().iter().skip(skip) {
            let kind = child.get_name();
            if !child.get_children().is_empty() {
                return Err(error("Nested pattern action"));
            }
            match kind {
                "align" => {
                    let offset = integer(child, "mark")? as u32;
                    let bits = integer(child, "bits")? as u32;
                    rule.alignment.push(Alignment { offset, mask: (1u32 << (bits & 31)).wrapping_sub(1) });
                }
                "funcstart" | "possiblefuncstart" | "codeboundary" | "setcontext" => {
                    let attributes = (0..child.get_num_attributes())
                        .map(|index| {
                            (
                                child.get_attribute_name(index).to_owned(),
                                String::from_utf8_lossy(child.get_attribute_value_at(index)).into_owned(),
                            )
                        })
                        .collect();
                    described.actions.push(FunctionPatternAction { kind: kind.to_owned(), attributes });
                }
                _ => return Err(error(format!("Unknown pattern subtag: {kind}"))),
            }
        }
        self.rules.push(rule);
        Arc::get_mut(&mut self.described).expect("rules are described while loading").push(described);
        Ok(self.rules.len() - 1)
    }

    fn byte_at(&self, pattern: &Pattern, index: usize) -> Byte {
        let pre = &self.sequences[pattern.pre].bytes;
        if index < pre.len() {
            pre[index]
        } else {
            self.sequences[pattern.post].bytes[index - pre.len()]
        }
    }

    fn add_pattern(&mut self, pre: usize, post: usize, rule: usize, mark: i32) -> Result<()> {
        let length = self.sequences[pre].bytes.len() + self.sequences[post].bytes.len();
        if length == 0 || length > i32::MAX as usize - 65536 {
            return Err(error("Pattern length exceeds native loader range"));
        }
        let mut pattern = Pattern { pre, post, rule, anchor: 0, length, mark };
        let mut best = -1i32;
        for index in 0..length {
            let bits = self.byte_at(&pattern, index).mask.count_ones() as i32;
            if bits >= best {
                best = bits;
                pattern.anchor = index;
            }
        }
        self.patterns.push(pattern);
        self.longest = self.longest.max(length);
        Ok(())
    }

    fn load_patterns(&mut self, root: &Element, file: &str) -> Result<()> {
        if root.get_name() != "patternlist" {
            return Err(error(format!("Expected patternlist in {file}")));
        }
        for element in root.get_children() {
            let children = element.get_children();
            match element.get_name() {
                "pattern" => {
                    let Some(first) = children.first() else {
                        return Err(error("Missing pattern data"));
                    };
                    let post = self.add_sequence(first)?;
                    let mut mark = integer(element, "mark")?;
                    if self.sequences[post].mark >= 0 {
                        mark = self.sequences[post].mark;
                    }
                    let rule = self.add_rule(element, 1, file)?;
                    self.add_pattern(0, post, rule, mark)?;
                }
                "patternpairs" => {
                    let total_bits = i64::from(integer(element, "totalbits")?);
                    let post_bits = i64::from(integer(element, "postbits")?);
                    let Some(prepatterns) = children.first().filter(|first| first.get_name() == "prepatterns") else {
                        return Err(error("Missing prepatterns"));
                    };
                    let mut pre = Vec::new();
                    for data in prepatterns.get_children() {
                        pre.push(self.add_sequence(data)?);
                    }
                    for group in children.iter().skip(1) {
                        if group.get_name() != "postpatterns" {
                            return Err(error("Expected postpatterns"));
                        }
                        let mut post = Vec::new();
                        let mut count = 0;
                        for data in group.get_children() {
                            if data.get_name() != "data" {
                                break;
                            }
                            count += 1;
                            let index = self.add_sequence(data)?;
                            if self.sequences[index].fixed >= post_bits {
                                post.push(index);
                            }
                        }
                        let rule = self.add_rule(group, count, file)?;
                        // Byte sequences and actions are shared across the
                        // Cartesian product.
                        for &p in &pre {
                            for &q in &post {
                                if self.sequences[p].fixed + self.sequences[q].fixed >= total_bits {
                                    let mark = self.sequences[p].bytes.len() as i32;
                                    self.add_pattern(p, q, rule, mark)?;
                                }
                            }
                        }
                    }
                }
                _ => return Err(error("Unknown patternlist element")),
            }
        }
        Ok(())
    }

    /// The pattern files `language`/`compiler` select under `root`, loaded
    /// (the console's `Search` constructor).
    fn open(root: &std::path::Path, language: &str, compiler: &str) -> Result<Self> {
        let mut directories: Vec<PathBuf> = Vec::new();
        scan_directory_recursive(&mut directories, "patterns", &root.join("Ghidra"), 4);
        directories.sort_by(|a, b| a.as_os_str().as_encoded_bytes().cmp(b.as_os_str().as_encoded_bytes()));
        let mut decisions = Decision::default();
        let mut found = false;
        for directory in &directories {
            let Ok(bytes) = std::fs::read(directory.join("patternconstraints.xml")) else {
                continue;
            };
            found = true;
            let document = xml_tree(&bytes).map_err(|e| error(format!("{}: {e}", directory.display())))?;
            let root = document.get_root();
            if root.get_name() != "patternconstraints" {
                return Err(error("Expected patternconstraints"));
            }
            load_decisions(&mut decisions, root)?;
        }
        if !found {
            return Err(error("No installed pattern constraints"));
        }
        let mut files = Vec::new();
        select_files(&decisions, language, compiler, &mut files)?;
        // A language whose own id selects nothing borrows the patterns of the
        // language it is built from. PSX:LE:32:default (native/languages/psx)
        // is Ghidra's MIPS32 plus the GTE and ships no pattern constraints of
        // its own, so it takes whatever the install registers for
        // MIPS:LE:32:default (Ghidra's, and an extension's such as
        // PsxLoader's R3000 set when installed). Without this alias no PSX
        // image matched a function start: Darkstalkers 3 decoded 15 k of its
        // 87 k instructions.
        if files.is_empty() {
            const ALIASES: &[(&str, &str)] = &[("PSX:LE:32:default", "MIPS:LE:32:default")];
            for (from, to) in ALIASES {
                if language == *from {
                    select_files(&decisions, to, compiler, &mut files)?;
                }
            }
        }
        files.sort();
        files.dedup();
        let mut set = Self {
            // The empty pre-sequence of direct patterns.
            sequences: vec![Sequence { mark: -1, ..Sequence::default() }],
            rules: Vec::new(),
            described: Arc::new(Vec::new()),
            patterns: Vec::new(),
            buckets: vec![Vec::new(); 256],
            longest: 0,
        };
        for file in &files {
            let mut loaded = false;
            for directory in &directories {
                let Ok(bytes) = std::fs::read(directory.join(file)) else {
                    continue;
                };
                let document = xml_tree(&bytes).map_err(|e| error(format!("{file}: {e}")))?;
                set.load_patterns(document.get_root(), file)?;
                loaded = true;
                break;
            }
            if !loaded {
                return Err(error(format!("Missing selected pattern file: {file}")));
            }
        }
        for index in 0..set.patterns.len() {
            let pattern = &set.patterns[index];
            let anchor = set.byte_at(pattern, pattern.anchor);
            // The second most constrained byte: the test that refuses a
            // candidate before its pattern is read.
            let mut second = (0u32, 0i32, Byte { mask: 0, value: 0 });
            for position in 0..pattern.length {
                let byte = set.byte_at(pattern, position);
                if position != pattern.anchor && byte.mask.count_ones() > second.0 {
                    second = (byte.mask.count_ones(), position as i32 - pattern.anchor as i32, byte);
                }
            }
            let candidate = Candidate { pattern: index as u32, offset: second.1, mask: second.2.mask, value: second.2.value };
            for byte in 0..=255u8 {
                if byte & anchor.mask == anchor.value {
                    set.buckets[usize::from(byte)].push(candidate);
                }
            }
        }
        Ok(set)
    }

    fn matches(sequence: &Sequence, bytes: &[u8]) -> bool {
        sequence.bytes.iter().zip(bytes).all(|(byte, &actual)| actual & byte.mask == byte.value)
    }

    /// Every (mark address, rule) a pattern matches in `ranges` (sorted,
    /// merged, `start < end`), the bytes read through `fill`. A pattern
    /// whose mark lies outside the range it matched in does not count.
    fn scan(
        &self,
        ranges: &[(u64, u64)],
        fill: &mut dyn FnMut(u64, &mut [u8]) -> Result<()>,
    ) -> Result<Vec<(u64, usize)>> {
        let mut hits = Vec::new();
        if self.patterns.is_empty() || ranges.is_empty() {
            return Ok(hits);
        }
        const WINDOW: usize = 65536;
        let capacity = WINDOW + self.longest - 1;
        let mut buffer = vec![0u8; capacity];
        for &(range_start, range_end) in ranges {
            let mut cursor = range_start;
            while cursor < range_end {
                let starts = (range_end - cursor).min(WINDOW as u64) as usize;
                let available = (range_end - cursor).min(capacity as u64) as usize;
                fill(cursor, &mut buffer[..available])?;
                for position in 0..available {
                    for candidate in &self.buckets[usize::from(buffer[position])] {
                        // A second byte of the pattern that cannot match refuses it
                        // here (a byte past the window is left to the full test).
                        let second = position as i64 + i64::from(candidate.offset);
                        if candidate.mask != 0
                            && (0..available as i64).contains(&second)
                            && buffer[second as usize] & candidate.mask != candidate.value
                        {
                            continue;
                        }
                        let pattern = &self.patterns[candidate.pattern as usize];
                        if position < pattern.anchor {
                            continue;
                        }
                        let start = position - pattern.anchor;
                        if start >= starts || pattern.length > available - start {
                            continue;
                        }
                        let rule = &self.rules[pattern.rule];
                        let raw = cursor + start as u64;
                        if rule
                            .alignment
                            .iter()
                            .any(|alignment| (raw as u32).wrapping_add(alignment.offset) & alignment.mask != 0)
                        {
                            continue;
                        }
                        let pre = &self.sequences[pattern.pre];
                        if !Self::matches(pre, &buffer[start..])
                            || !Self::matches(&self.sequences[pattern.post], &buffer[start + pre.bytes.len()..])
                        {
                            continue;
                        }
                        let mark = if pattern.mark < 0 {
                            let back = u64::from(pattern.mark.unsigned_abs());
                            if back > raw - range_start {
                                continue;
                            }
                            raw - back
                        } else {
                            if u64::from(pattern.mark as u32) >= range_end - raw {
                                continue;
                            }
                            raw + pattern.mark as u64
                        };
                        hits.push((mark, pattern.rule));
                    }
                }
                cursor += starts as u64;
            }
        }
        hits.sort_unstable();
        hits.dedup();
        Ok(hits)
    }
}

/// Loaded pattern sets by Ghidra install, language and compiler: the files
/// are the same for every image of a language, and a discovery round
/// searches again.
fn pattern_set(root: &std::path::Path, language: &str, compiler: &str) -> Result<Arc<PatternSet>> {
    type Key = (PathBuf, String, String);
    static CACHE: LazyLock<Mutex<HashMap<Key, Arc<PatternSet>>>> = LazyLock::new(Default::default);
    let key = (root.to_path_buf(), language.to_owned(), compiler.to_owned());
    if let Some(found) = CACHE.lock().unwrap_or_else(|error| error.into_inner()).get(&key) {
        return Ok(Arc::clone(found));
    }
    let set = Arc::new(PatternSet::open(root, language, compiler)?);
    CACHE.lock().unwrap_or_else(|error| error.into_inner()).insert(key, Arc::clone(&set));
    Ok(set)
}

impl SleighLifter {
    /// The function-start pattern matches in `ranges` of the loaded image
    /// (`start < end`, byte-backed: the image refuses a read past its bytes),
    /// under the language's pattern files.
    pub(crate) fn function_patterns(&mut self, ranges: &[(u64, u64)]) -> Result<FunctionPatterns> {
        let mut scaled: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
        let space = &self.code_space;
        for &(start, end) in ranges {
            if start >= end {
                return Err(error("invalid function-pattern search range"));
            }
            scaled.push((
                kuna_base::space::AddrSpace::address_to_byte(start, space.get_word_size()),
                kuna_base::space::AddrSpace::address_to_byte(end, space.get_word_size()),
            ));
        }
        scaled.sort_unstable();
        let mut count = 0;
        for index in 0..scaled.len() {
            let range = scaled[index];
            if count != 0 && range.0 <= scaled[count - 1].1 {
                scaled[count - 1].1 = scaled[count - 1].1.max(range.1);
            } else {
                scaled[count] = range;
                count += 1;
            }
        }
        scaled.truncate(count);
        let set = pattern_set(&self.ghidra_root, &self.language_id, &self.compiler_id)?;
        let loader = self.sleigh.loader_rc();
        let code_space = Rc::clone(&self.code_space);
        let hits = set.scan(&scaled, &mut |offset, buffer| {
            loader
                .borrow_mut()
                .load_fill(buffer, &Address::new(Rc::clone(&code_space), offset))
                .map_err(|e| error(format!("function-pattern search: {e}")))
        })?;
        Ok(FunctionPatterns {
            alignment: self.sleigh.translate_base().get_alignment().max(0) as u64,
            rules: Arc::clone(&set.described),
            matches: hits.into_iter().map(|(address, rule)| FunctionPatternMatch { address, rule }).collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::{Mapping, NativeImport};
    use crate::session::RuntimeConfig;

    fn lifter(cfg: &RuntimeConfig, bytes: Vec<u8>) -> SleighLifter {
        let import = NativeImport {
            language: cfg.language_id.clone(),
            mappings: vec![Mapping { vaddr: 0x1000, size: bytes.len() as u64, file_off: 0, flags: 6, bytes }],
            ..Default::default()
        };
        SleighLifter::mapped(cfg, &import).unwrap()
    }

    fn addresses(lifter: &mut SleighLifter, end: u64) -> Vec<u64> {
        let found = lifter.function_patterns(&[(0x1000, end)]).unwrap();
        let mut addresses: Vec<u64> = found.matches.iter().map(|hit| hit.address).collect();
        addresses.sort_unstable();
        addresses.dedup();
        addresses
    }

    #[test]
    fn elf_pattern_selection_uses_loader_compiler() {
        let mut cfg = RuntimeConfig::from_env();
        if !cfg.ghidra_install.join("Ghidra").is_dir() {
            eprintln!("SKIP: no Ghidra install");
            return;
        }
        cfg.language_id = "x86:LE:64:default".into();
        cfg.language_dir = cfg.ghidra_install.join("Ghidra/Processors/x86/data/languages");
        // ELF64 with one allocated code section: ret; push rbp; mov rbp,rsp; ret.
        // The pinned GCC patterns recognize the entry after ret; Windows does not.
        let mut elf = vec![0u8; 0x200];
        elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        for (offset, value) in [(16, 2u16), (18, 62), (58, 64), (60, 2)] {
            elf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        }
        elf[40..48].copy_from_slice(&0x80u64.to_le_bytes());
        elf[0xc4..0xc8].copy_from_slice(&1u32.to_le_bytes());
        for (offset, value) in [(0xc8, 6u64), (0xd0, 0x1000), (0xd8, 0x180), (0xe0, 6)] {
            elf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        elf[0x180..0x186].copy_from_slice(&[0xc3, 0x55, 0x48, 0x89, 0xe5, 0xc3]);
        let mut import = crate::native::import_elf(&elf).unwrap();
        crate::native::select_language(&mut import, &cfg).unwrap();
        let mut lifter = SleighLifter::mapped(&cfg, &import).unwrap();
        let found = lifter.function_patterns(&[(0x1000, 0x1006)]).unwrap();
        assert!(
            found.matches.iter().any(|hit| hit.address == 0x1001),
            "ELF compiler selection must recognize the GCC entry: {found:?}"
        );
    }

    #[test]
    fn function_pattern_queries_preserve_prefix_marks_and_range_bounds() {
        let mut cfg = RuntimeConfig::from_env();
        if !cfg.ghidra_install.join("Ghidra").is_dir() {
            eprintln!("SKIP: no Ghidra install");
            return;
        }
        cfg.language_id = "AARCH64:LE:64:v8A".into();
        cfg.language_dir = cfg.ghidra_install.join("Ghidra/Processors/AARCH64/data/languages");
        let cases: &[(&[u32], &[u64])] = &[
            // ret; nop; stp x29,x30,[sp,#-32]!; mov x29,sp; ret.
            // Both the wildcard prefix and the pair's post-pattern mark match.
            (&[0xd65f03c0, 0xd503201f, 0xa9be7bfd, 0x910003fd, 0xd65f03c0], &[0x1004, 0x1008]),
            // ret; sub sp,sp,#16; add sp,sp,#16; ret: pair-only match.
            (&[0xd65f03c0, 0xd10043ff, 0x910043ff, 0xd65f03c0], &[0x1004]),
        ];
        for &(words, expected) in cases {
            let bytes: Vec<_> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
            let end = 0x1000 + bytes.len() as u64;
            let mut lifter = lifter(&cfg, bytes);
            assert_eq!(addresses(&mut lifter, end).as_slice(), expected);
            assert!(
                addresses(&mut lifter, 0x1007).is_empty(),
                "a pattern must not read past the requested mapped range"
            );
        }

        // A private pattern root exercises DSL boundaries without modifying the SDK.
        struct PatternRoot(PathBuf);
        impl Drop for PatternRoot {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let root = std::env::temp_dir().join(format!("romwright-pattern-grammar-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let root = PatternRoot(root);
        let patterns = root.0.join("Ghidra/Processors/Fixture/data/patterns");
        std::fs::create_dir_all(&patterns).unwrap();
        std::fs::write(
            patterns.join("patternconstraints.xml"),
            r#"
<patternconstraints><language id="AARCH64:*:64:*">
  <patternfile>grammar.xml</patternfile>
  <compiler id="not-the-selected-compiler"><patternfile>missing.xml</patternfile></compiler>
</language></patternconstraints>"#,
        )
        .unwrap();
        std::fs::write(
            patterns.join("grammar.xml"),
            r#"
<patternlist>
  <pattern mark="0"><data>0xa. * 1011....</data>
    <align mark="0x100000001" bits="2"/><possiblefuncstart/>
  </pattern>
  <patternpairs totalbits="9" postbits="4">
    <prepatterns><data>0xc.</data></prepatterns>
    <postpatterns><data>0xd.</data><funcstart/></postpatterns>
  </patternpairs>
  <patternpairs totalbits="8" postbits="5">
    <prepatterns><data>0xe.</data></prepatterns>
    <postpatterns><data>0xf.</data><funcstart/></postpatterns>
  </patternpairs>
</patternlist>"#,
        )
        .unwrap();
        cfg.ghidra_install = root.0.clone();
        let mut bytes = vec![0; 0x10002];
        bytes[3..5].copy_from_slice(&[0xa1, 0xb2]);
        bytes[0xffff..0x10001].copy_from_slice(&[0xa3, 0xb4]);
        bytes[0x13..0x15].copy_from_slice(&[0xc1, 0xd2]);
        bytes[0x17..0x19].copy_from_slice(&[0xe3, 0xf4]);
        let mut lifter = lifter(&cfg, bytes);
        assert_eq!(
            addresses(&mut lifter, 0x11002),
            vec![0x1004, 0x11000],
            "marks override attributes; alignment uses the raw start; fixed-bit thresholds apply"
        );
        assert_eq!(
            addresses(&mut lifter, 0x11000),
            vec![0x1004],
            "a match across a scan-buffer boundary still needs its complete byte sequence"
        );
    }

    #[test]
    fn sequences_and_integers_read_as_ghidra_reads_them() {
        let parse = |text: &str| {
            let document = xml_tree(format!("<data>{text}</data>").as_bytes()).unwrap();
            sequence(document.get_root()).map(|sequence| {
                (sequence.bytes.iter().map(|byte| (byte.value, byte.mask)).collect::<Vec<_>>(), sequence.mark, sequence.fixed)
            })
        };
        assert_eq!(parse("0xa. * 1011....").unwrap(), (vec![(0xa0, 0xf0), (0xb0, 0xf0)], 1, 8));
        assert_eq!(parse("10.00001 # comment\n0x00").unwrap(), (vec![(0x81, 0xff - 0x20), (0, 0xff)], -1, 15));
        assert!(parse("0x0").is_err());
        assert!(parse("2").is_err());
        let integer = |text: &str| {
            let document = xml_tree(format!("<a v=\"{text}\"/>").as_bytes()).unwrap();
            integer(document.get_root(), "v")
        };
        assert_eq!(integer("0x10").unwrap(), 16);
        assert_eq!(integer("010").unwrap(), 8);
        assert_eq!(integer("-3").unwrap(), -3);
        assert_eq!(integer("0xffffffff").unwrap(), -1);
        assert_eq!(integer("0x100000001").unwrap(), 1);
        assert!(integer("08").is_err());
        assert!(language_matches("x86:*:64:*", "x86:LE:64:default"));
        assert!(!language_matches("x86:*:64", "x86:LE:64:default"));
    }
}
