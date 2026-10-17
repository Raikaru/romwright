//! Hand-built printer IR, mirroring what native/romwright_printir.hh writes.

use super::ir::kind;
use crate::doc::decode_tokens;
use romwright_model::TokenKind;

#[derive(Default)]
struct Blob(Vec<u8>);

impl Blob {
    fn u(&mut self, mut value: u64) -> &mut Self {
        loop {
            let byte = 0x40 | (value & 0x3f) as u8;
            value >>= 6;
            self.0.push(if value != 0 { byte | 0x80 } else { byte });
            if value == 0 {
                return self;
            }
        }
    }
    fn s(&mut self, value: i64) -> &mut Self {
        self.u(((value << 1) ^ (value >> 63)) as u64)
    }
    fn flag(&mut self, value: bool) -> &mut Self {
        self.u(u64::from(value))
    }
    fn str(&mut self, value: &str) -> &mut Self {
        self.u(value.len() as u64);
        self.0.extend_from_slice(value.as_bytes());
        self
    }
    fn bytes(&mut self, value: &[u8]) -> &mut Self {
        self.u(value.len() as u64);
        self.0.extend_from_slice(value);
        self
    }
    /// Event codes are single raw bytes (`RomwrightCaptureEmit`).
    fn code(&mut self, code: u8) -> &mut Self {
        self.0.push(code);
        self
    }
}

/// Fragment event writers (RomwrightCaptureEmit codes).
#[derive(Default)]
struct Frag(Blob, u64);

impl Frag {
    fn print(mut self, text: &str) -> Self {
        self.0.code(26).str(text).u(8);
        self
    }
    fn keyword(mut self, text: &str) -> Self {
        self.0.code(26).str(text).u(0);
        self
    }
    fn var(mut self, name: &str, varnode: u64) -> Self {
        self.0
            .code(17)
            .str(name)
            .u(4)
            .flag(true)
            .u(varnode)
            .flag(false);
        self
    }
    fn op(mut self, name: &str, op: u64) -> Self {
        self.0.code(18).str(name).u(8).flag(true).u(op);
        self
    }
    fn spaces(mut self, count: i64) -> Self {
        self.0.code(31).s(count).s(0);
        self
    }
    fn group(mut self, inner: impl FnOnce(Self) -> Self) -> Self {
        self.1 += 1;
        let id = self.1;
        self.0.code(29).u(id);
        let mut inner = inner(self);
        inner.0.code(30).u(id);
        inner
    }
    fn paren(mut self, inner: impl FnOnce(Self) -> Self) -> Self {
        self.1 += 1;
        let id = self.1;
        self.0.code(27).u(id).str("(");
        let mut inner = inner(self);
        inner.0.code(28).u(id).str(")");
        inner
    }
    fn done(self) -> Vec<u8> {
        self.0.0
    }
}

fn header(blob: &mut Blob, declaration: Vec<u8>, body_nodes: u64) {
    blob.0.extend_from_slice(b"RWPI");
    blob.u(7).s(100).s(2);
    blob.u(2).u(0).u(0).u(0); // skip_line function braces, same_line otherwise
    blob.s(40); // countbase after PrintC's docFunction
    blob.u(2).u(0).bytes(b"L"); // options: hide_exts; no forced mods; size suffix
    blob.flag(false); // the decompiler cast (casts pending: no)
    blob.flag(false); // the decompiler merged (merge owner: no)
    blob.bytes(&[]).bytes(&declaration).bytes(&[]);
    blob.u(0).u(0); // no symbols, no types
    blob.u(4).u(0).u(0); // the size of int; no core types, no type orders
    blob.flag(true); // the decompiler's own block tree
    blob.u(body_nodes);
}

/// Renders the blob with the (empty) unstructured-graph section version 5
/// ends with: no blocks, no for-loops, no complemented `if`s.
fn render_blob(blob: &Blob) -> Result<Vec<u8>, String> {
    let mut bytes = blob.0.clone();
    bytes.extend_from_slice(&[0x40, 0x40, 0x40]);
    super::render(&bytes)
}

fn declaration() -> Vec<u8> {
    Frag::default()
        .keyword("void")
        .spaces(1)
        .group(|f| f.print("f").paren(|f| f.keyword("void")))
        .done()
}

/// `x = value;` rooted at op `time`.
fn assignment(time: u64, value: &str) -> Vec<u8> {
    Frag::default()
        .group(|f| f.var("x", 1).spaces(1).op("=", time).spaces(1).print(value))
        .done()
}

/// `LAB_<index>`, as `emitLabel` writes a block's label.
fn label(index: i64) -> Vec<u8> {
    let mut blob = Blob::default();
    blob.code(24)
        .str(&format!("LAB_{index:08x}"))
        .u(0)
        .flag(false)
        .u(1)
        .u(index as u64);
    blob.0
}

fn copy_of_basic(
    blob: &mut Blob,
    index: i64,
    statements: &[(u64, Vec<u8>)],
    branch: Option<(Vec<u8>, Vec<u8>)>,
    successors: &[i64],
) {
    blob.u(kind::COPY).s(index).flag(false).flag(false).u(1);
    blob.u(kind::BASIC).s(index).flag(false).flag(false);
    blob.u(0); // comments
    blob.u(statements.len() as u64);
    for (time, fragment) in statements {
        blob.u(*time).flag(false).u(0).bytes(fragment).flag(false);
        // effect: opcode COPY, no call, no store, no output, no flip, no inputs
        blob.u(1).flag(false).flag(false).flag(false).flag(false).u(0);
        // print tree: no written variable; a root the worker does not print
        blob.flag(false).u(0).bytes(b"test");
    }
    match branch {
        Some((normal, comma)) => {
            blob.flag(true).bytes(&normal).flag(true).bytes(&comma);
            blob.flag(false).flag(false).u(0).bytes(b"test"); // own print tree
        }
        None => {
            blob.flag(false);
        }
    }
    blob.u(successors.len() as u64);
    for successor in successors {
        blob.s(*successor);
    }
    blob.flag(false).flag(false); // no negated condition, no loop op
    blob.bytes(&label(index));
}

fn text(markup: &[u8]) -> String {
    let mut out = String::new();
    for token in decode_tokens(markup) {
        if token.kind == TokenKind::Break {
            out.push('\n');
            out.push_str(&" ".repeat(token.indent.unwrap_or(0) as usize));
        } else {
            out.push_str(&token.text);
        }
    }
    out
}

#[test]
fn prints_a_straight_line_function() {
    let mut blob = Blob::default();
    header(&mut blob, declaration(), 1);
    copy_of_basic(
        &mut blob,
        0,
        &[(1, assignment(1, "1")), (2, assignment(2, "2"))],
        None,
        &[],
    );
    let markup = render_blob(&blob).unwrap();
    assert_eq!(
        text(&markup),
        "\nvoid f(void)\n\n{\n  x = 1;\n  x = 2;\n}\n"
    );
}

#[test]
fn paren_ids_continue_from_printc_counter() {
    let mut blob = Blob::default();
    header(&mut blob, declaration(), 1);
    copy_of_basic(&mut blob, 0, &[(1, assignment(1, "1"))], None, &[]);
    let mut bytes = blob.0.clone();
    bytes.extend_from_slice(&[0x40, 0x40, 0x40]);
    let ir = super::ir::decode(&bytes).unwrap();
    let (_, consumed) = super::printer::print_function(&ir, 0).unwrap();
    let markup = super::print(&ir).unwrap();
    let (again, _) = super::printer::print_function(&ir, 40 - consumed).unwrap();
    assert_eq!(markup, again);
    assert!(consumed > 0);
}

#[test]
fn prints_if_else_if_with_pending_brace() {
    let mut blob = Blob::default();
    header(&mut blob, declaration(), 1);
    let condition = |time: u64, name: &str| {
        let normal = Frag::default().paren(|f| f.var(name, time)).done();
        let comma = Frag::default().group(|f| f.var(name, time)).done();
        (normal, comma)
    };
    // if (a) { x = 1; } else if (b) { x = 2; }
    blob.u(kind::IF).s(10).flag(false).flag(false).u(3);
    copy_of_basic(&mut blob, 1, &[], Some(condition(3, "a")), &[3, 2]);
    copy_of_basic(&mut blob, 2, &[(4, assignment(4, "1"))], None, &[5]);
    blob.u(kind::IF).s(11).flag(false).flag(false).u(2);
    copy_of_basic(&mut blob, 3, &[], Some(condition(5, "b")), &[5, 4]);
    copy_of_basic(&mut blob, 4, &[(6, assignment(6, "2"))], None, &[5]);
    blob.u(0).flag(false); // inner if: no goto
    blob.u(0).flag(false); // outer if: no goto
    let markup = render_blob(&blob).unwrap();
    assert_eq!(
        text(&markup),
        "\nvoid f(void)\n\n{\n  if (a) {\n    x = 1;\n  }\n  else if (b) {\n    x = 2;\n  }\n}\n"
    );
}

#[test]
fn long_statements_break_inside_their_groups() {
    let mut blob = Blob::default();
    header(&mut blob, declaration(), 1);
    let long = "a".repeat(60);
    let statement = Frag::default()
        .group(|f| {
            f.var(&long, 1)
                .spaces(1)
                .op("=", 1)
                .spaces(1)
                .group(|f| f.var(&long, 2).spaces(1).op("+", 1).spaces(1).print("1"))
        })
        .done();
    copy_of_basic(&mut blob, 0, &[(1, statement)], None, &[]);
    let markup = render_blob(&blob).unwrap();
    let rendered = text(&markup);
    assert!(rendered.lines().all(|line| line.len() <= 100), "{rendered}");
    assert!(rendered.contains(&format!("{long} =\n")), "{rendered}");
}

#[test]
fn sections_split_printc_markup_from_the_ir() {
    use crate::wire::{ELEMENT_END, ELEMENT_START, encode_header, encode_string_attribute};
    let mut doc = Vec::new();
    encode_header(&mut doc, ELEMENT_START, crate::wire::elem::DOC);
    for _ in 0..2 {
        encode_header(&mut doc, ELEMENT_START, crate::wire::elem::FUNCTION);
        encode_header(&mut doc, ELEMENT_END, crate::wire::elem::FUNCTION);
    }
    encode_header(&mut doc, ELEMENT_START, super::ELEM_PRINTIR);
    encode_string_attribute(&mut doc, 1, b"RWPI\x02");
    encode_header(&mut doc, ELEMENT_END, super::ELEM_PRINTIR);
    encode_header(&mut doc, ELEMENT_END, crate::wire::elem::DOC);
    let sections = super::sections(&doc).unwrap();
    assert_eq!(sections.printer_ir, Some(b"RWPI\x02".as_slice()));
    // FUNCTION (116) needs a two-byte header: open plus close is four bytes.
    assert_eq!(sections.markup.map(<[u8]>::len), Some(4));
}

/// One block of a structuring query (`native/romwright_structure.hh`,
/// `romwrightEncodeShape`): `outs` are `(target, back_edge)`; the in-edges
/// are given by the caller as `(source, slot at the source)`.
fn query_block(blob: &mut Blob, last: u64, ins: &[(i64, u64)], outs: &[(i64, u64, bool)]) {
    blob.u(0).u(last); // flags, last-op kind
    blob.flag(false); // no last-op time
    blob.flag(false).flag(false).flag(false); // fall-through, complex, flipped
    blob.u(ins.len() as u64);
    for &(source, slot) in ins {
        blob.s(source).u(slot).u(0);
    }
    blob.u(outs.len() as u64);
    for &(target, slot, back) in outs {
        blob.s(target).u(slot).u(if back { 0x82 } else { 0 });
    }
}

fn varints(answer: &[u8]) -> Vec<u64> {
    let mut values = Vec::new();
    let (mut value, mut shift) = (0u64, 0);
    for &byte in answer {
        value |= u64::from(byte & 0x3f) << shift;
        shift += 6;
        if byte & 0x80 == 0 {
            values.push(value);
            (value, shift) = (0, 0);
        }
    }
    values
}

#[test]
fn a_structuring_query_names_the_if_else_and_the_return() {
    // 0 -> {1, 2}; 1 -> 3; 2 -> 3; 3 returns: an if/else, nothing negated,
    // no goto into the return.
    let mut blob = Blob::default();
    blob.u(4);
    query_block(&mut blob, 2, &[], &[(1, 0, false), (2, 0, false)]);
    query_block(&mut blob, 3, &[(0, 0)], &[(3, 0, false)]);
    query_block(&mut blob, 3, &[(0, 1)], &[(3, 1, false)]);
    query_block(&mut blob, 1, &[(1, 0), (2, 0)], &[]);
    let answer = varints(&super::query::answer(&blob.0).unwrap());
    // flips: none; returns: block 3 with no slots; one if/else whose split is
    // block 0; no loops.
    assert_eq!(answer, vec![0, 1, 3, 0, 1, 1, 0, 0]);
}

#[test]
fn a_structuring_query_that_does_not_parse_is_an_error() {
    assert!(super::query::answer(&[0x41]).is_err());
}
