//! Decompiler tokens as the source view consumes them (Qt `TokenView`):
//! text, a kind on the shared highlighter scale, the entity address the
//! document carried, the callee a function-name token follows, and the
//! stored parameter declarations that become argument hints.

use crate::code;
use crate::theme::Syntax;
use romwright_model::function_ir::{IrOperation, Operand, OperationId};
use romwright_model::{Address, DecompDoc, DecompToken, TokenKind};
use std::collections::{BTreeMap, HashMap};

/// Ghidra `ClangToken` colour classes the worker forwards (`ATTRIB_COLOR`);
/// 0 doubles as the decoder's default, so it only means "keyword" on words.
const COLOR_COMMENT: u8 = 1;
const COLOR_TYPE: u8 = 2;
const COLOR_FUNCTION: u8 = 3;
const COLOR_CONSTANT: u8 = 5;
const COLOR_PARAMETER: u8 = 6;
const COLOR_GLOBAL: u8 = 7;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Ends a line; `indent` is the next line's indentation.
    Break,
    /// A stored parameter declaration shown before a call argument; never
    /// part of copied source.
    Hint,
    /// Structural punctuation and operators (argument-hint depth counting).
    Syntax,
    /// A function name; `function_target` is where it leads.
    Function,
    /// Everything else, already classified.
    Code(Syntax),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Token {
    pub text: String,
    pub kind: Kind,
    pub address: Option<Address>,
    pub indent: usize,
    pub function_target: Option<Address>,
    pub parameters: Vec<String>,
}

impl Token {
    pub fn new(text: impl Into<String>, kind: Kind) -> Self {
        Self { text: text.into(), kind, address: None, indent: 0, function_target: None, parameters: Vec::new() }
    }

    pub fn line_break(indent: usize) -> Self {
        Self { indent, ..Self::new("", Kind::Break) }
    }

    pub fn syntax(&self) -> Syntax {
        match self.kind {
            Kind::Break => Syntax::Plain,
            Kind::Hint => Syntax::Dim,
            Kind::Syntax => code::decompiler_kind("Syntax"),
            Kind::Function => code::decompiler_kind("FuncName"),
            Kind::Code(syntax) => syntax,
        }
    }
}

/// Worker token kind plus colour class, on the shared highlighter names.
fn classify(token: &DecompToken, warning: bool) -> Kind {
    let by_color = |fallback: &'static str| -> &'static str {
        match token.color {
            COLOR_COMMENT => "Comment",
            COLOR_TYPE => "Type",
            COLOR_FUNCTION => "FuncName",
            COLOR_CONSTANT => "Constant",
            COLOR_PARAMETER => "Param",
            COLOR_GLOBAL => "Global",
            _ => fallback,
        }
    };
    let name = match token.kind {
        TokenKind::Break => return Kind::Break,
        TokenKind::FuncName => return Kind::Function,
        TokenKind::Comment if warning => "Warning",
        TokenKind::Comment => "Comment",
        TokenKind::Type => "Type",
        TokenKind::Field | TokenKind::Bitfield => "Field",
        TokenKind::Label => "Global",
        TokenKind::Variable | TokenKind::Value => by_color("Variable"),
        TokenKind::Op => return Kind::Syntax,
        TokenKind::Syntax => {
            let word = token.text.bytes().any(|byte| byte.is_ascii_alphabetic())
                && token.text.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
            match token.color {
                0 if word => "Keyword",
                COLOR_COMMENT if warning => "Warning",
                COLOR_COMMENT => "Comment",
                _ => return Kind::Syntax,
            }
        }
        TokenKind::Other => by_color("Plain"),
    };
    if name == "FuncName" {
        return Kind::Function;
    }
    Kind::Code(code::decompiler_kind(name))
}

/// `(int a, char *b)` → `["int a", "char *b"]`. Templates, unbalanced
/// brackets and `void`/`...` lists give no hints (Qt
/// `parameterDeclarations`).
pub fn parameter_declarations(signature: &str) -> Vec<String> {
    let (Some(open), Some(close)) = (signature.find('('), signature.rfind(')')) else { return Vec::new() };
    if close <= open || signature.contains('<') || signature.contains('>') {
        return Vec::new();
    }
    let mut result = Vec::new();
    let mut depth = 0i32;
    let mut start = open + 1;
    for (index, c) in signature[..=close].char_indices().skip_while(|(index, _)| *index <= open) {
        if index == close || (c == ',' && depth == 0) {
            if depth != 0 {
                return Vec::new();
            }
            let parameter = signature[start..index].trim();
            if parameter.is_empty() || parameter == "void" || parameter == "..." {
                break;
            }
            result.push(parameter.to_string());
            start = index + 1;
        } else if c == '(' || c == '[' {
            depth += 1;
        } else if c == ')' || c == ']' {
            if depth == 0 {
                return Vec::new();
            }
            depth -= 1;
        }
    }
    result
}

fn blank(token: &Token) -> bool {
    token.kind == Kind::Break || token.text.trim().is_empty()
}

/// Inserts a hint token before the first token of every argument of a call
/// whose callee has stored parameter declarations (Qt `withArgumentHints`).
pub fn with_argument_hints(source: Vec<Token>) -> Vec<Token> {
    let mut hints: BTreeMap<usize, String> = BTreeMap::new();
    for (index, token) in source.iter().enumerate() {
        if token.parameters.is_empty() {
            continue;
        }
        let mut open = index + 1;
        while open < source.len() && blank(&source[open]) {
            open += 1;
        }
        if open == source.len() || source[open].text != "(" {
            continue;
        }
        let (mut depth, mut parameter, mut first) = (1i32, 0usize, true);
        let mut cursor = open + 1;
        while cursor < source.len() && depth > 0 {
            let argument = &source[cursor];
            cursor += 1;
            if blank(argument) {
                continue;
            }
            if first && argument.text != ")" && parameter < token.parameters.len() {
                hints.entry(cursor - 1).or_default().push_str(&format!("{}: ", token.parameters[parameter]));
                first = false;
            }
            if argument.kind != Kind::Syntax {
                continue;
            }
            for c in argument.text.chars() {
                match c {
                    '(' | '[' | '{' => depth += 1,
                    ')' | ']' | '}' => depth -= 1,
                    ',' if depth == 1 => {
                        parameter += 1;
                        first = true;
                    }
                    _ => {}
                }
            }
        }
    }
    let mut result = Vec::with_capacity(source.len() + hints.len());
    for (index, token) in source.into_iter().enumerate() {
        if let Some(hint) = hints.remove(&index) {
            result.push(Token::new(hint, Kind::Hint));
        }
        result.push(token);
    }
    result
}

/// The document's tokens with operation addresses, call targets and
/// argument hints resolved (Qt `TokenView::fromDocument`). `entry` is the
/// containing function's entry (`DecompiledFunction::function_entry`).
pub fn from_document(doc: &DecompDoc, signatures: &BTreeMap<u64, String>, entry: Option<&Address>) -> Vec<Token> {
    let operations: HashMap<OperationId, &IrOperation> = doc
        .function_ir
        .iter()
        .flat_map(|ir| ir.blocks.iter().flat_map(|block| &block.operations))
        .map(|operation| (operation.id, operation))
        .collect();
    let mut result = Vec::with_capacity(doc.tokens.len());
    let mut declaration_seen = false;
    let mut warning = false;
    for token in &doc.tokens {
        if token.kind == TokenKind::Comment || token.color == COLOR_COMMENT {
            // `/*` may be its own token; the marker can follow it.
            if token.text.starts_with("/*") || token.text.starts_with("//") {
                warning = token.text.contains("WARNING");
            } else if token.text.contains("WARNING") {
                warning = true;
            }
        } else if token.kind == TokenKind::Break {
            warning = false;
        }
        let kind = classify(token, warning);
        let mut view = Token {
            text: token.text.clone(),
            kind,
            address: token.address.clone(),
            indent: token.indent.and_then(|indent| usize::try_from(indent).ok()).unwrap_or(0),
            function_target: None,
            parameters: Vec::new(),
        };
        if kind == Kind::Function {
            view.function_target = view.address.clone();
        }
        if let Some(operation) = token.operation.and_then(|id| operations.get(&id)) {
            if view.address.is_none() {
                view.address = Some(operation.address.clone());
            }
            if kind == Kind::Function && operation.opcode == romwright_model::function_ir::Opcode::CALL {
                let target = match operation.inputs.first() {
                    Some(Operand::Value(value)) => doc
                        .function_ir
                        .as_ref()
                        .and_then(|ir| ir.values.get(value))
                        .and_then(|value| value.offset)
                        .map(Address::ram),
                    _ => None,
                }
                .or_else(|| doc.call_targets.get(&operation.id).cloned());
                if let Some(target) = &target {
                    view.parameters = signatures.get(&target.offset).map(|signature| parameter_declarations(signature)).unwrap_or_default();
                }
                view.function_target = target;
            }
        } else if kind == Kind::Function && !declaration_seen {
            declaration_seen = true;
            if view.address.is_none() {
                view.address = Some(entry.cloned().unwrap_or_else(|| doc.address.clone()));
                view.function_target = entry.cloned();
            }
        }
        result.push(view);
    }
    with_argument_hints(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameter_declarations_split_top_level_commas() {
        assert_eq!(parameter_declarations("int f(int a, void (*cb)(int, int), char b[4])"), ["int a", "void (*cb)(int, int)", "char b[4]"]);
        assert!(parameter_declarations("void f(void)").is_empty());
        assert!(parameter_declarations("T<int> f(int a)").is_empty());
        assert!(parameter_declarations("int f(int a").is_empty());
    }

    #[test]
    fn hints_precede_each_argument() {
        let mut call = Token::new("use", Kind::Function);
        call.parameters = vec!["int count".into(), "char *name".into()];
        let tokens = vec![
            call,
            Token::new("(", Kind::Syntax),
            Token::new("42", Kind::Code(Syntax::Constant)),
            Token::new(",", Kind::Syntax),
            Token::new(" ", Kind::Syntax),
            Token::new("s", Kind::Code(Syntax::Variable)),
            Token::new(")", Kind::Syntax),
        ];
        let texts: Vec<_> = with_argument_hints(tokens).into_iter().map(|token| token.text).collect();
        assert_eq!(texts, ["use", "(", "int count: ", "42", ",", " ", "char *name: ", "s", ")"]);
    }
}
