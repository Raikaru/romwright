//! The one code highlighter. Listing text is classified into [`Syntax`]
//! kinds here, decompiler token kinds map onto the same kinds, and
//! [`CodePainter`] draws monospace spans with the soft occurrence highlight
//! every code view shares (hover or click an identifier to see the others).

use crate::theme::{Syntax, Theme, metrics};
use egui::{Align2, CornerRadius, FontId, Painter, Pos2, Rect, pos2, vec2};
use std::ops::Range;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Span {
    pub range: Range<usize>,
    pub kind: Syntax,
}

fn is_word_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || matches!(byte, b'_' | b'$' | b'.' | b'%' | b'@')
}

fn is_word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$' | b'.' | b'@')
}

/// Register names across the architectures Romwright decodes. Matching is
/// case-insensitive; `%`/`$` prefixes (AT&T, MIPS) are accepted.
pub fn is_register(word: &str) -> bool {
    let lower = word.trim_start_matches(['%', '$']).to_ascii_lowercase();
    let word = lower.as_str();
    const NAMED: &[&str] = &[
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip", "eax", "ebx", "ecx", "edx",
        "esi", "edi", "ebp", "esp", "eip", "ax", "bx", "cx", "dx", "si", "di", "bp", "sp", "ip",
        "al", "bl", "cl", "dl", "ah", "bh", "ch", "dh", "sil", "dil", "bpl", "spl", "cs", "ds",
        "es", "fs", "gs", "ss", "lr", "pc", "ctr", "xer", "msr", "cpsr", "spsr", "fp", "zero",
        "at", "gp", "ra", "xzr", "wzr", "hi", "lo", "sb", "sl", "ip0", "ip1", "fpscr", "flags",
        "eflags", "rflags", "sr", "pr", "macl", "mach", "gbr", "vbr", "a", "x", "y", "hl", "de",
        "bc", "ix", "iy", "af",
    ];
    if NAMED.contains(&word) {
        return true;
    }
    let numbered = |prefix: &str, max: u32| {
        word.strip_prefix(prefix)
            .and_then(|digits| {
                let digits = digits.trim_end_matches(['d', 'w', 'b', 'h']);
                (!digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())).then(|| digits.parse::<u32>().ok())
            })
            .flatten()
            .is_some_and(|number| number <= max)
    };
    numbered("r", 31)
        || numbered("x", 30)
        || numbered("w", 30)
        || numbered("v", 31)
        || numbered("q", 31)
        || numbered("d", 31)
        || numbered("s", 31)
        || numbered("f", 31)
        || numbered("xmm", 31)
        || numbered("ymm", 31)
        || numbered("zmm", 31)
        || numbered("st", 7)
        || numbered("mm", 7)
        || numbered("k", 7)
        || numbered("cr", 15)
        || numbered("dr", 15)
        || numbered("t", 9)
        || numbered("a", 7)
}

fn is_size_keyword(word: &str) -> bool {
    matches!(
        word.to_ascii_lowercase().as_str(),
        "byte" | "word" | "dword" | "qword" | "tword" | "xmmword" | "ymmword" | "zmmword" | "ptr"
            | "short" | "near" | "far" | "lock" | "rep" | "repe" | "repne" | "repz" | "repnz"
    )
}

/// Classifies one rendered instruction (`mnemonic operands`). The first
/// word is the mnemonic; operands become registers, numbers, symbols and
/// punctuation. Hex values of 0x1000 and up read as addresses (followable),
/// smaller ones as constants.
pub fn highlight_instruction(text: &str) -> Vec<Span> {
    let bytes = text.as_bytes();
    let mut spans = Vec::new();
    let mut index = 0;
    let mut seen_mnemonic = false;
    while index < bytes.len() {
        let start = index;
        let byte = bytes[index];
        if byte.is_ascii_whitespace() {
            while index < bytes.len() && bytes[index].is_ascii_whitespace() {
                index += 1;
            }
            spans.push(Span { range: start..index, kind: Syntax::Plain });
            continue;
        }
        if byte.is_ascii_digit() || (byte == b'-' && bytes.get(index + 1).is_some_and(u8::is_ascii_digit)) {
            index += 1;
            while index < bytes.len() && (bytes[index].is_ascii_alphanumeric()) {
                index += 1;
            }
            let word = &text[start..index];
            let kind = match word.strip_prefix("0x").or_else(|| word.strip_prefix("0X")) {
                Some(hex) if u64::from_str_radix(hex, 16).is_ok_and(|value| value >= 0x1000) => Syntax::Address,
                _ => Syntax::Constant,
            };
            spans.push(Span { range: start..index, kind });
            continue;
        }
        if is_word_start(byte) {
            index += 1;
            while index < bytes.len() && is_word(bytes[index]) {
                index += 1;
            }
            let word = &text[start..index];
            let prefix = matches!(
                word.to_ascii_lowercase().as_str(),
                "lock" | "rep" | "repe" | "repne" | "repz" | "repnz"
            );
            let kind = if !seen_mnemonic && prefix {
                Syntax::Keyword
            } else if !seen_mnemonic {
                seen_mnemonic = true;
                Syntax::Mnemonic
            } else if is_register(word) {
                Syntax::Register
            } else if is_size_keyword(word) {
                Syntax::Keyword
            } else {
                Syntax::Label
            };
            spans.push(Span { range: start..index, kind });
            continue;
        }
        if byte == b'"' || byte == b'\'' {
            index += 1;
            while index < bytes.len() && bytes[index] != byte {
                index += 1;
            }
            index = (index + 1).min(bytes.len());
            spans.push(Span { range: start..index, kind: Syntax::String });
            continue;
        }
        if byte == b';' || byte == b'#' && bytes.get(index + 1) == Some(&b' ') {
            spans.push(Span { range: start..bytes.len(), kind: Syntax::Comment });
            break;
        }
        // One UTF-8 scalar of punctuation.
        let width = text[index..].chars().next().map_or(1, char::len_utf8);
        index += width;
        spans.push(Span { range: start..index, kind: Syntax::Punctuation });
    }
    spans
}

/// Decompiler token kinds (worker `DecompToken.kind`) on the shared scale.
pub fn decompiler_kind(kind: &str) -> Syntax {
    match kind {
        "Keyword" => Syntax::Keyword,
        "Type" => Syntax::Type,
        "FuncName" => Syntax::Function,
        "Variable" | "Param" | "Field" => Syntax::Variable,
        "Global" => Syntax::Label,
        "Constant" => Syntax::Constant,
        "String" => Syntax::String,
        "Comment" => Syntax::Comment,
        "Error" | "Warning" => Syntax::Warning,
        "Syntax" | "Operator" => Syntax::Punctuation,
        _ => Syntax::Plain,
    }
}

/// The identifier-like word spanning byte `column` of `text`, used for
/// occurrence highlighting and operand following.
pub fn word_at(text: &str, column: usize) -> Option<Range<usize>> {
    let bytes = text.as_bytes();
    if column >= bytes.len() || !is_word(bytes[column]) {
        return None;
    }
    let mut start = column;
    while start > 0 && (is_word(bytes[start - 1]) || bytes[start - 1] == b'%') {
        start -= 1;
    }
    let mut end = column + 1;
    while end < bytes.len() && is_word(bytes[end]) {
        end += 1;
    }
    Some(start..end)
}

/// Draws monospace spans on a line. Every code view goes through this so the
/// occurrence highlight and colours are identical everywhere.
pub struct CodePainter<'a> {
    pub painter: &'a Painter,
    pub theme: &'a Theme,
    pub font: FontId,
    pub char_width: f32,
    pub row_height: f32,
    /// Word whose occurrences get the soft highlight.
    pub occurrence: Option<&'a str>,
}

impl CodePainter<'_> {
    /// Width of `columns` monospace cells.
    pub fn columns(&self, columns: usize) -> f32 {
        self.char_width * columns as f32
    }

    /// Draws `text` at `origin` (top-left of the row) in one colour.
    pub fn text(&self, origin: Pos2, text: &str, kind: Syntax) {
        self.text_colored(origin, text, self.theme.syntax(kind));
    }

    pub fn text_colored(&self, origin: Pos2, text: &str, color: egui::Color32) {
        if text.is_empty() {
            return;
        }
        let y = origin.y + self.row_height / 2.0;
        self.painter.text(pos2(origin.x, y), Align2::LEFT_CENTER, text, self.font.clone(), color);
    }

    /// Draws classified spans; occurrences of the highlighted word get a
    /// rounded accent wash behind them.
    pub fn spans(&self, origin: Pos2, text: &str, spans: &[Span]) {
        for span in spans {
            let piece = &text[span.range.clone()];
            let x = origin.x + self.columns(text[..span.range.start].chars().count());
            if self.occurrence.is_some_and(|word| word == piece) {
                let width = self.columns(piece.chars().count());
                let rect = Rect::from_min_size(pos2(x - 1.0, origin.y + 2.0), vec2(width + 2.0, self.row_height - 4.0));
                self.painter.rect_filled(rect, CornerRadius::same(metrics::RADIUS_SM), self.theme.accent_soft);
            }
            if span.kind != Syntax::Plain || !piece.trim().is_empty() {
                self.text(pos2(x, origin.y), piece, span.kind);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(text: &str) -> Vec<(String, Syntax)> {
        highlight_instruction(text)
            .into_iter()
            .filter(|span| span.kind != Syntax::Plain)
            .map(|span| (text[span.range].to_string(), span.kind))
            .collect()
    }

    #[test]
    fn instruction_parts_get_shared_kinds() {
        assert_eq!(
            kinds("MOV qword ptr [RSP + 0x8],RAX"),
            vec![
                ("MOV".into(), Syntax::Mnemonic),
                ("qword".into(), Syntax::Keyword),
                ("ptr".into(), Syntax::Keyword),
                ("[".into(), Syntax::Punctuation),
                ("RSP".into(), Syntax::Register),
                ("+".into(), Syntax::Punctuation),
                ("0x8".into(), Syntax::Constant),
                ("]".into(), Syntax::Punctuation),
                (",".into(), Syntax::Punctuation),
                ("RAX".into(), Syntax::Register),
            ]
        );
        assert_eq!(kinds("CALL 0x401000")[1], ("0x401000".into(), Syntax::Address));
        assert_eq!(kinds("bl memcpy")[1], ("memcpy".into(), Syntax::Label));
        assert_eq!(kinds("addiu $sp,$sp,-0x20")[1], ("$sp".into(), Syntax::Register));
    }

    #[test]
    fn word_at_finds_identifiers_and_hex() {
        let text = "JMP 0x4010a0";
        assert_eq!(word_at(text, 6).map(|r| &text[r]), Some("0x4010a0"));
        assert_eq!(word_at(text, 3), None);
        assert!(is_register("xmm15") && is_register("%eax") && !is_register("memcpy"));
    }
}
