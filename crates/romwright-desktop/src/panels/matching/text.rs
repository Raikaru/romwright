//! Text layouts for the matching workspace: C source with pin washes, the
//! unified diff, JSON diagnostics and objdiff instruction cells. Every
//! colour is a theme syntax token, so source here reads like the decompiler.

use crate::code;
use crate::theme::{Syntax, Theme, Type, font};
use egui::text::{LayoutJob, TextFormat};
use egui::{Color32, FontId};
use std::ops::Range;

const C_KEYWORDS: &[&str] = &[
    "auto", "break", "case", "const", "continue", "default", "do", "else", "enum", "extern", "for", "goto", "if",
    "inline", "register", "restrict", "return", "sizeof", "static", "struct", "switch", "typedef", "union",
    "volatile", "while", "asm", "__asm", "__attribute__", "class", "namespace", "template", "this", "new", "delete",
    "true", "false", "nullptr", "NULL",
];

const C_TYPES: &[&str] = &[
    "void", "char", "short", "int", "long", "float", "double", "signed", "unsigned", "bool", "_Bool", "size_t",
    "u8", "u16", "u32", "u64", "s8", "s16", "s32", "s64", "f32", "f64", "uint8_t", "uint16_t", "uint32_t",
    "uint64_t", "int8_t", "int16_t", "int32_t", "int64_t", "uintptr_t", "intptr_t",
];

fn word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Classifies C/C++ source into shared syntax kinds.
pub fn highlight_c(text: &str) -> Vec<(Range<usize>, Syntax)> {
    let bytes = text.as_bytes();
    let mut spans = Vec::new();
    let mut index = 0;
    let mut line_start = true;
    while index < bytes.len() {
        let start = index;
        let byte = bytes[index];
        let kind = if byte == b'\n' {
            index += 1;
            line_start = true;
            spans.push((start..index, Syntax::Plain));
            continue;
        } else if byte.is_ascii_whitespace() {
            while index < bytes.len() && bytes[index] != b'\n' && bytes[index].is_ascii_whitespace() {
                index += 1;
            }
            spans.push((start..index, Syntax::Plain));
            continue;
        } else if line_start && byte == b'#' {
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            Syntax::Keyword
        } else if text[index..].starts_with("//") {
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            Syntax::Comment
        } else if text[index..].starts_with("/*") {
            index = text[index + 2..].find("*/").map_or(bytes.len(), |end| index + 2 + end + 2);
            Syntax::Comment
        } else if byte == b'"' || byte == b'\'' {
            index += 1;
            while index < bytes.len() && bytes[index] != byte && bytes[index] != b'\n' {
                index += if bytes[index] == b'\\' { 2 } else { 1 };
            }
            index = (index + 1).min(bytes.len());
            Syntax::String
        } else if byte.is_ascii_digit() {
            while index < bytes.len() && (word(bytes[index]) || bytes[index] == b'.') {
                index += 1;
            }
            Syntax::Constant
        } else if word(byte) {
            while index < bytes.len() && word(bytes[index]) {
                index += 1;
            }
            let name = &text[start..index];
            let next = text[index..].trim_start().as_bytes().first().copied();
            if C_TYPES.contains(&name) {
                Syntax::Type
            } else if C_KEYWORDS.contains(&name) {
                Syntax::Keyword
            } else if next == Some(b'(') {
                Syntax::Function
            } else {
                Syntax::Variable
            }
        } else {
            index += text[index..].chars().next().map_or(1, char::len_utf8);
            Syntax::Punctuation
        };
        line_start = false;
        spans.push((start..index, kind));
    }
    spans
}

fn format(font: &FontId, color: Color32, background: Color32) -> TextFormat {
    TextFormat { font_id: font.clone(), color, background, ..Default::default() }
}

/// Highlighted C source; `pins` (UTF-8 byte ranges) get the warning wash.
pub fn source_job(text: &str, theme: &Theme, pins: &[Range<usize>]) -> LayoutJob {
    let font = font(Type::Code);
    let wash = theme.warn.gamma_multiply(0.28);
    let mut job = LayoutJob::default();
    // Split every span at pin edges so a pin may start mid-token.
    let mut cuts: Vec<usize> = pins.iter().flat_map(|pin| [pin.start, pin.end]).filter(|cut| *cut <= text.len()).collect();
    cuts.sort_unstable();
    for (range, kind) in highlight_c(text) {
        let mut start = range.start;
        for cut in cuts.iter().copied().filter(|cut| *cut > range.start && *cut < range.end).chain([range.end]) {
            if !text.is_char_boundary(cut) {
                continue;
            }
            let pinned = pins.iter().any(|pin| pin.start <= start && cut <= pin.end && pin.start < pin.end);
            let background = if pinned { wash } else { Color32::TRANSPARENT };
            job.append(&text[start..cut], 0.0, format(&font, theme.syntax(kind), background));
            start = cut;
        }
    }
    job
}

/// A unified diff: additions, removals and hunk headers in state colours.
pub fn diff_job(text: &str, theme: &Theme) -> LayoutJob {
    let font = font(Type::Code);
    let mut job = LayoutJob::default();
    for line in text.split_inclusive('\n') {
        let (color, background) = if line.starts_with("+++") || line.starts_with("---") {
            (theme.text, Color32::TRANSPARENT)
        } else if line.starts_with('+') {
            (theme.ok, theme.ok.gamma_multiply(0.12))
        } else if line.starts_with('-') {
            (theme.error, theme.error.gamma_multiply(0.12))
        } else if line.starts_with("@@") {
            (theme.accent, Color32::TRANSPARENT)
        } else {
            (theme.text_muted, Color32::TRANSPARENT)
        };
        job.append(line, 0.0, format(&font, color, background));
    }
    job
}

/// Pretty JSON with keys, strings, numbers and literals told apart.
pub fn json_job(text: &str, theme: &Theme) -> LayoutJob {
    let font = font(Type::Code);
    let bytes = text.as_bytes();
    let mut job = LayoutJob::default();
    let mut index = 0;
    while index < bytes.len() {
        let start = index;
        let kind = match bytes[index] {
            b'"' => {
                index += 1;
                while index < bytes.len() && bytes[index] != b'"' {
                    index += if bytes[index] == b'\\' { 2 } else { 1 };
                }
                index = (index + 1).min(bytes.len());
                let key = text[index..].trim_start().starts_with(':');
                if key { Syntax::Variable } else { Syntax::String }
            }
            b'-' | b'0'..=b'9' => {
                while index < bytes.len() && matches!(bytes[index], b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9') {
                    index += 1;
                }
                Syntax::Constant
            }
            byte if byte.is_ascii_alphabetic() => {
                while index < bytes.len() && bytes[index].is_ascii_alphabetic() {
                    index += 1;
                }
                Syntax::Keyword
            }
            _ => {
                index += text[index..].chars().next().map_or(1, char::len_utf8);
                Syntax::Punctuation
            }
        };
        job.append(&text[start..index], 0.0, format(&font, theme.syntax(kind), Color32::TRANSPARENT));
    }
    job
}

/// One objdiff instruction cell, coloured like the listing.
pub fn instruction_job(text: &str, theme: &Theme) -> LayoutJob {
    let font = font(Type::CodeSmall);
    let mut job = LayoutJob::default();
    let mut end = 0;
    for span in code::highlight_instruction(text) {
        if span.range.start > end {
            job.append(&text[end..span.range.start], 0.0, format(&font, theme.text, Color32::TRANSPARENT));
        }
        job.append(&text[span.range.clone()], 0.0, format(&font, theme.syntax(span.kind), Color32::TRANSPARENT));
        end = span.range.end;
    }
    if end < text.len() {
        job.append(&text[end..], 0.0, format(&font, theme.text, Color32::TRANSPARENT));
    }
    job
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(text: &str) -> Vec<(&str, Syntax)> {
        highlight_c(text).into_iter().filter(|(_, kind)| *kind != Syntax::Plain).map(|(range, kind)| (&text[range], kind)).collect()
    }

    #[test]
    fn c_source_gets_shared_kinds() {
        assert_eq!(
            kinds("#include \"types.h\"\nint f(u8 x) { return x + 2; } /* ü */"),
            vec![
                ("#include \"types.h\"", Syntax::Keyword),
                ("int", Syntax::Type),
                ("f", Syntax::Function),
                ("(", Syntax::Punctuation),
                ("u8", Syntax::Type),
                ("x", Syntax::Variable),
                (")", Syntax::Punctuation),
                ("{", Syntax::Punctuation),
                ("return", Syntax::Keyword),
                ("x", Syntax::Variable),
                ("+", Syntax::Punctuation),
                ("2", Syntax::Constant),
                (";", Syntax::Punctuation),
                ("}", Syntax::Punctuation),
                ("/* ü */", Syntax::Comment),
            ]
        );
    }

    #[test]
    fn source_layout_covers_every_byte_and_splits_at_pins() {
        let text = "/* é */ return x + 12;";
        let theme = Theme::new(crate::theme::ThemeName::Dark);
        let pin = text.find("12").unwrap();
        let job = source_job(text, &theme, std::slice::from_ref(&(pin..pin + 1)));
        assert_eq!(job.text, text);
        assert!(job.sections.iter().any(|section| &text[section.byte_range.start.0..section.byte_range.end.0] == "1" && section.format.background != Color32::TRANSPARENT));
        assert_eq!(json_job("{\"a\": [1, true, \"x\"]}", &theme).text, "{\"a\": [1, true, \"x\"]}");
        assert_eq!(diff_job("--- a\n+++ b\n@@ -1 +1 @@\n-x\n+y\n", &theme).text.len(), 30);
    }
}
