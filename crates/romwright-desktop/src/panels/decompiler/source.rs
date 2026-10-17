//! The decompiler's read-only source model (Qt `DecompilerView` minus the
//! widget): flattened text, token spans, address index, brace folding,
//! cursor/selection, hint-free copy and the keyboard contract. The panel
//! paints it; the UI gate drives it headlessly (`ui.source.*`).

use super::tokens::{Kind, Token};
use crate::code;
use crate::theme::Syntax;
use egui::{Event, Key};
use romwright_model::Address;
use std::collections::{BTreeSet, HashMap};
use std::ops::Range;

#[derive(Clone, Copy, Debug)]
struct Span {
    start: usize,
    end: usize,
    token: usize,
}

/// What a key or clipboard event asks the owner to do.
#[derive(Clone, Debug, PartialEq)]
pub enum Action {
    /// Ctrl+Enter / Ctrl+click on a function name.
    Follow(Address),
    /// F2 on a function name: the address and its current name.
    Rename(Address, String),
    /// Ctrl+C: the selection with argument hints removed.
    Copy(String),
}

#[derive(Default)]
pub struct SourceView {
    tokens: Vec<Token>,
    hints_hidden: bool,
    text: String,
    line_starts: Vec<usize>,
    spans: Vec<Span>,
    addresses: HashMap<Address, Vec<usize>>,
    fold_ends: Vec<Option<usize>>,
    /// Open braces at the start of each line (indent guides).
    depths: Vec<usize>,
    folded: BTreeSet<usize>,
    visible: Vec<usize>,
    highlight: Option<Address>,
    cursor: usize,
    anchor: usize,
    reveal: bool,
    longest_line: usize,
    indent_unit: usize,
}

impl SourceView {
    pub fn set_tokens(&mut self, tokens: Vec<Token>) {
        self.tokens = tokens;
        self.rebuild();
        self.cursor = 0;
        self.anchor = 0;
    }

    fn rebuild(&mut self) {
        self.spans.clear();
        self.addresses.clear();
        self.folded.clear();
        self.highlight = None;
        self.text.clear();
        for (index, token) in self.tokens.iter().enumerate() {
            if token.kind == Kind::Break {
                self.text.push('\n');
                self.text.extend(std::iter::repeat_n(' ', token.indent));
            } else if !token.text.is_empty() && (!self.hints_hidden || token.kind != Kind::Hint) {
                let start = self.text.len();
                self.spans.push(Span { start, end: start + token.text.len(), token: index });
                if let Some(address) = &token.address {
                    self.addresses.entry(address.clone()).or_default().push(start);
                }
                self.text.push_str(&token.text);
            }
        }
        self.line_starts = std::iter::once(0)
            .chain(self.text.match_indices('\n').map(|(index, _)| index + 1))
            .collect();
        self.longest_line = (0..self.line_count()).map(|line| self.line(line).chars().count()).max().unwrap_or(0);
        self.indent_unit = (0..self.line_count())
            .map(|line| {
                let text = self.line(line);
                if text.trim().is_empty() { 0 } else { text.len() - text.trim_start_matches(' ').len() }
            })
            .filter(|indent| *indent > 0)
            .min()
            .unwrap_or(2);
        self.find_folds();
        self.apply_folds();
    }

    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }

    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn hints_visible(&self) -> bool {
        !self.hints_hidden
    }

    /// Toggles argument hints, keeping the cursor on its line.
    pub fn set_hints_visible(&mut self, visible: bool) {
        if visible == !self.hints_hidden {
            return;
        }
        let line = self.line_of(self.cursor);
        self.hints_hidden = !visible;
        self.rebuild();
        self.cursor = self.line_range(line.min(self.line_count() - 1)).start;
        self.anchor = self.cursor;
    }

    pub fn line_count(&self) -> usize {
        self.line_starts.len()
    }

    /// The document's indentation step (smallest non-zero indent).
    pub fn indent_unit(&self) -> usize {
        self.indent_unit
    }

    pub fn longest_line(&self) -> usize {
        self.longest_line
    }

    pub fn line_range(&self, line: usize) -> Range<usize> {
        let start = self.line_starts[line];
        let end = self.line_starts.get(line + 1).map_or(self.text.len(), |next| next - 1);
        start..end
    }

    pub fn line(&self, line: usize) -> &str {
        &self.text[self.line_range(line)]
    }

    pub fn line_of(&self, position: usize) -> usize {
        self.line_starts.partition_point(|start| *start <= position).saturating_sub(1)
    }

    /// Lines not hidden inside a folded block, in order.
    pub fn visible_lines(&self) -> &[usize] {
        &self.visible
    }

    /// Byte position of character `column` on `line`, clamped to its end.
    pub fn position(&self, line: usize, column: usize) -> usize {
        let range = self.line_range(line);
        range.start + self.text[range.clone()].char_indices().nth(column).map_or(range.len(), |(index, _)| index)
    }

    pub fn column_of(&self, position: usize) -> usize {
        let start = self.line_range(self.line_of(position)).start;
        self.text[start..position].chars().count()
    }

    /// Spans on `line` as line-local byte ranges with their tokens.
    pub fn line_spans(&self, line: usize) -> impl Iterator<Item = (Range<usize>, &Token)> {
        let range = self.line_range(line);
        let first = self.spans.partition_point(|span| span.end <= range.start);
        self.spans[first..]
            .iter()
            .take_while(move |span| span.start < range.end)
            .map(move |span| (span.start - range.start..span.end - range.start, &self.tokens[span.token]))
    }

    pub fn token_at(&self, position: usize) -> Option<&Token> {
        let index = self.spans.partition_point(|span| span.start <= position).checked_sub(1)?;
        let span = self.spans[index];
        (position < span.end).then(|| &self.tokens[span.token])
    }

    fn span_at(&self, position: usize) -> Option<Span> {
        let index = self.spans.partition_point(|span| span.start <= position).checked_sub(1)?;
        Some(self.spans[index]).filter(|span| position < span.end)
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    pub fn cursor_line(&self) -> usize {
        self.line_of(self.cursor)
    }

    pub fn selection(&self) -> Option<Range<usize>> {
        (self.anchor != self.cursor).then(|| self.anchor.min(self.cursor)..self.anchor.max(self.cursor))
    }

    pub fn selected_text(&self) -> &str {
        self.selection().map_or("", |range| &self.text[range])
    }

    /// Moves the cursor; `extend` keeps the anchor (Shift).
    pub fn set_cursor(&mut self, position: usize, extend: bool) {
        self.cursor = self.boundary(position.min(self.text.len()));
        if !extend {
            self.anchor = self.cursor;
        }
        self.reveal = true;
    }

    fn boundary(&self, mut position: usize) -> usize {
        while !self.text.is_char_boundary(position) {
            position -= 1;
        }
        position
    }

    pub fn select(&mut self, range: Range<usize>) {
        self.anchor = range.start;
        self.cursor = range.end;
        self.reveal = true;
    }

    pub fn select_all(&mut self) {
        self.select(0..self.text.len());
    }

    /// Double click: the identifier or token under `position`.
    pub fn select_word(&mut self, position: usize) {
        let line = self.line_range(self.line_of(position));
        let local = position - line.start;
        if let Some(word) = code::word_at(&self.text[line.clone()], local) {
            self.select(line.start + word.start..line.start + word.end);
        } else if let Some(span) = self.span_at(position) {
            self.select(span.start..span.end);
        }
    }

    pub fn select_line(&mut self, line: usize) {
        let range = self.line_range(line);
        let end = if line + 1 < self.line_count() { range.end + 1 } else { range.end };
        self.select(range.start..end);
    }

    /// Asks the owner to scroll the cursor into view once.
    pub fn take_reveal(&mut self) -> bool {
        std::mem::take(&mut self.reveal)
    }

    /// The address of the token under the cursor, else of the first
    /// addressed token on the cursor's line.
    pub fn current_address(&self) -> Option<&Address> {
        if let Some(address) = self.token_at(self.cursor).and_then(|token| token.address.as_ref()) {
            return Some(address);
        }
        let line = self.line_range(self.cursor_line());
        let first = self.spans.partition_point(|span| span.start < line.start);
        self.spans[first..]
            .iter()
            .take_while(|span| span.start <= line.end)
            .find_map(|span| self.tokens[span.token].address.as_ref())
    }

    /// Byte ranges of every token tied to the synced address.
    pub fn highlighted(&self) -> Vec<Range<usize>> {
        let Some(positions) = self.highlight.as_ref().and_then(|address| self.addresses.get(address)) else { return Vec::new() };
        positions
            .iter()
            .filter_map(|position| self.span_at(*position))
            .filter(|span| !self.is_comment(span.token))
            .map(|span| span.start..span.end)
            .collect()
    }

    /// Comments carry their function's address but are not code for it.
    fn is_comment(&self, token: usize) -> bool {
        matches!(self.tokens[token].syntax(), Syntax::Comment | Syntax::Warning)
    }

    /// Reverse sync from another view: highlight the address's tokens and,
    /// unless the analyst holds a selection, put the cursor on the first one,
    /// unfolding blocks that hide it (Qt `setAddress`).
    pub fn set_address(&mut self, address: &Address) {
        self.highlight = Some(address.clone());
        let Some(positions) = self.addresses.get(address) else { return };
        let code = positions.iter().find(|position| self.span_at(**position).is_some_and(|span| !self.is_comment(span.token)));
        let Some(&position) = code.or(positions.first()) else { return };
        if self.current_address() == Some(address) || self.selection().is_some() {
            return;
        }
        let line = self.line_of(position);
        let before = self.folded.len();
        let ends = &self.fold_ends;
        self.folded.retain(|folded| !(*folded < line && ends[*folded].is_some_and(|end| end >= line)));
        if self.folded.len() != before {
            self.apply_folds();
        }
        self.set_cursor(position, false);
    }

    /// The selection as copied: argument hints removed.
    pub fn copy_selection(&self) -> Option<String> {
        let range = self.selection()?;
        let mut text = String::with_capacity(range.len());
        let mut at = range.start;
        let first = self.spans.partition_point(|span| span.end <= range.start);
        for span in self.spans[first..].iter().take_while(|span| span.start < range.end) {
            if self.tokens[span.token].kind != Kind::Hint {
                continue;
            }
            let (start, end) = (span.start.max(range.start), span.end.min(range.end));
            text.push_str(&self.text[at..start]);
            at = end;
        }
        text.push_str(&self.text[at..range.end]);
        Some(text)
    }

    /// The function a name token leads to, when the cursor sits on one (or
    /// selects exactly it), with the name.
    pub fn follow_target(&self) -> Option<(Address, String)> {
        let start = self.selection().map_or(self.cursor, |range| range.start);
        let token = self.token_at(start)?;
        let target = token.function_target.clone()?;
        (self.selection().is_none() || self.selected_text() == token.text).then(|| (target, token.text.clone()))
    }

    // ----- folding --------------------------------------------------------

    pub fn fold_end(&self, line: usize) -> Option<usize> {
        self.fold_ends.get(line).copied().flatten().filter(|end| *end > line)
    }

    pub fn is_folded(&self, line: usize) -> bool {
        self.folded.contains(&line)
    }

    pub fn toggle_fold(&mut self, line: usize) {
        let Some(end) = self.fold_end(line) else { return };
        if !self.folded.remove(&line) {
            self.folded.insert(line);
            let cursor_line = self.cursor_line();
            if cursor_line > line && cursor_line <= end {
                self.set_cursor(self.line_range(line).start, false);
            }
        }
        self.apply_folds();
    }

    /// Ctrl+Shift+[: folds the innermost block containing the cursor.
    pub fn fold_current(&mut self) {
        let cursor_line = self.cursor_line();
        let found = (0..=cursor_line).rev().find(|line| self.fold_end(*line).is_some_and(|end| end > cursor_line));
        if let Some(line) = found {
            self.toggle_fold(line);
        }
    }

    pub fn expand_all(&mut self) {
        self.folded.clear();
        self.apply_folds();
    }

    /// Brace nesting at the start of `line`: indent guides follow blocks,
    /// not alignment whitespace.
    pub fn depth(&self, line: usize) -> usize {
        self.depths.get(line).copied().unwrap_or(0)
    }

    pub fn is_line_visible(&self, line: usize) -> bool {
        self.visible.binary_search(&line).is_ok()
    }

    /// Brace pairs spanning lines, ignoring comments and literals.
    fn find_folds(&mut self) {
        self.fold_ends = vec![None; self.line_count()];
        self.depths = vec![0; self.line_count()];
        let bytes = self.text.as_bytes();
        let mut stack = Vec::new();
        let (mut line, mut index) = (0usize, 0usize);
        let (mut quote, mut comment, mut line_comment, mut escaped) = (None, false, false, false);
        while index < bytes.len() {
            let (c, next) = (bytes[index], bytes.get(index + 1).copied());
            index += 1;
            if c == b'\n' {
                line += 1;
                line_comment = false;
                if let Some(depth) = self.depths.get_mut(line) {
                    *depth = stack.len();
                }
            }
            if line_comment {
                continue;
            }
            if comment {
                if c == b'*' && next == Some(b'/') {
                    comment = false;
                    index += 1;
                }
                continue;
            }
            if let Some(open) = quote {
                if escaped {
                    escaped = false;
                } else if c == b'\\' {
                    escaped = true;
                } else if c == open {
                    quote = None;
                }
                continue;
            }
            match (c, next) {
                (b'/', Some(b'*')) => {
                    comment = true;
                    index += 1;
                }
                (b'/', Some(b'/')) => {
                    line_comment = true;
                    index += 1;
                }
                (b'"' | b'\'', _) => quote = Some(c),
                (b'{', _) => stack.push(line),
                (b'}', _) => {
                    if let Some(start) = stack.pop()
                        && line > start
                    {
                        self.fold_ends[start] = Some(line);
                    }
                }
                _ => {}
            }
        }
    }

    fn apply_folds(&mut self) {
        let mut depth_changes = vec![0i32; self.line_count() + 1];
        for line in &self.folded {
            if let Some(end) = self.fold_ends[*line] {
                depth_changes[line + 1] += 1;
                depth_changes[end + 1] -= 1;
            }
        }
        let mut depth = 0;
        self.visible.clear();
        for (line, change) in depth_changes.iter().enumerate().take(self.line_count()) {
            depth += change;
            if depth == 0 {
                self.visible.push(line);
            }
        }
    }

    // ----- keyboard -------------------------------------------------------

    fn move_lines(&mut self, delta: isize, extend: bool) {
        let column = self.column_of(self.cursor);
        let line = self.cursor_line();
        let index = self.visible.partition_point(|visible| *visible < line) as isize;
        let target = (index + delta).clamp(0, self.visible.len() as isize - 1) as usize;
        let position = self.position(self.visible[target], column);
        self.set_cursor(position, extend);
    }

    fn step(&self, forward: bool) -> usize {
        if forward {
            self.text[self.cursor..].chars().next().map_or(self.cursor, |c| self.cursor + c.len_utf8())
        } else {
            self.text[..self.cursor].chars().next_back().map_or(self.cursor, |c| self.cursor - c.len_utf8())
        }
    }

    /// Applies one input event. The view is read-only: typed text and
    /// paste never change it. `page` is the visible line count.
    pub fn handle_event(&mut self, event: &Event, page: usize) -> Option<Action> {
        match event {
            Event::Copy => return self.copy_selection().map(Action::Copy),
            Event::Key { key, pressed: true, modifiers, .. } => {
                if self.text.is_empty() && self.tokens.is_empty() {
                    return None;
                }
                let (shift, command) = (modifiers.shift, modifiers.command);
                match key {
                    Key::ArrowLeft | Key::ArrowRight => {
                        let forward = *key == Key::ArrowRight;
                        match self.selection() {
                            Some(range) if !shift => self.set_cursor(if forward { range.end } else { range.start }, false),
                            _ => self.set_cursor(self.step(forward), shift),
                        }
                    }
                    Key::ArrowUp => self.move_lines(-1, shift),
                    Key::ArrowDown => self.move_lines(1, shift),
                    Key::PageUp => self.move_lines(-(page.max(2) as isize - 1), shift),
                    Key::PageDown => self.move_lines(page.max(2) as isize - 1, shift),
                    Key::Home if command => self.set_cursor(0, shift),
                    Key::End if command => self.set_cursor(self.text.len(), shift),
                    Key::Home => self.set_cursor(self.line_range(self.cursor_line()).start, shift),
                    Key::End => self.set_cursor(self.line_range(self.cursor_line()).end, shift),
                    Key::A if command => self.select_all(),
                    Key::C if command => return self.copy_selection().map(Action::Copy),
                    Key::Enter if command => return self.follow_target().map(|(target, _)| Action::Follow(target)),
                    Key::F2 => return self.follow_target().map(|(target, name)| Action::Rename(target, name)),
                    Key::OpenBracket | Key::OpenCurlyBracket if command && shift => self.fold_current(),
                    Key::CloseBracket | Key::CloseCurlyBracket if command && shift => self.expand_all(),
                    _ => {}
                }
            }
            _ => {}
        }
        None
    }
}
