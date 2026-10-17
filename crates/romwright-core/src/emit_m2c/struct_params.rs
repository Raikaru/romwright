//! A parameter the decompiler typed with a struct, under a declaration that
//! does not name it.
//!
//! An asserted prototype is the project's own declaration, and its `void *`
//! (a struct the project's header does not let an import see) replaces the
//! printed signature. The body still reads the parameter by member
//! (`param_1->field_0x8`), which `void *` cannot do, so each such use takes
//! the cast that says what the decompiler typed it as: `((S *)param_1)->field_0x8`.
//! The cast changes no code the compiler emits: it is the access a member
//! expression through `S *` would have been.

use romwright_model::{DecompDoc, DecompType};

/// The struct a parameter points at, when the decompiler typed it with one.
///
/// The worker reports a pointee as the `<typeref>` the decompiler wrote: a name
/// and an id, no metatype. A struct is therefore told by its metatype where
/// the type carries one, and otherwise by being a name the inference makes.
fn pointee_struct(ty: &DecompType) -> Option<&str> {
    if ty.metatype.as_deref() != Some("ptr") {
        return None;
    }
    let target = ty.target.as_deref()?;
    let name = target.name.as_deref()?;
    (target.metatype.as_deref() == Some("struct") || romwright_model::structs::is_inferred_name(name))
        .then_some(name)
}

fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Whether `text` holds `word` as a whole identifier.
fn names(text: &str, word: &str) -> bool {
    let bytes = text.as_bytes();
    text.match_indices(word).any(|(at, _)| {
        (at == 0 || !is_word_byte(bytes[at - 1]))
            && bytes.get(at + word.len()).is_none_or(|next| !is_word_byte(*next))
    })
}

/// `body` with every use of a struct-typed parameter whose declared type (in
/// the printed signature) does not name the struct cast to it. Bodies whose
/// signature names the struct are returned as they are.
pub(super) fn cast_struct_params(doc: &DecompDoc, body: String) -> String {
    let Some(prototype) = doc.prototype.as_ref() else { return body };
    let Some(open) = body.find('{') else { return body };
    let (header, rest) = body.split_at(open);
    let mut rest = rest.to_string();
    for parameter in &prototype.parameters {
        let Some(structure) = pointee_struct(&parameter.data_type) else { continue };
        if names(header, structure) {
            continue;
        }
        rest = cast_uses(&rest, &parameter.name, structure);
    }
    format!("{header}{rest}")
}

/// Whether the occurrence of a name at `at..end` changes it or takes its
/// address, so that a cast (which is not an lvalue) cannot stand in for it.
fn is_written(text: &str, at: usize, end: usize) -> bool {
    let after = text[end..].trim_start_matches([' ', '\t']);
    let assigns = (after.starts_with('=') && !after.starts_with("=="))
        || ["+=", "-=", "*=", "/=", "|=", "&=", "^=", "<<=", ">>=", "++", "--"].iter().any(|op| after.starts_with(op));
    let before = text[..at].trim_end_matches([' ', '\t']);
    let prefix = before.ends_with("++") || before.ends_with("--");
    let address = before.ends_with('&')
        && !before.ends_with("&&")
        && !before[..before.len() - 1]
            .trim_end_matches([' ', '\t'])
            .bytes()
            .last()
            .is_some_and(|c| is_word_byte(c) || c == b')' || c == b']');
    // `&param_1->f`, `param_1[2] = 0`, `++param_1->n` act on what it points at.
    let through = after.starts_with("->") || after.starts_with('[') || after.starts_with('.');
    !through && (assigns || prefix || address)
}

/// Replaces every use of `name` by `((structure *)name)`: the type the
/// decompiler read it as, in a member access, an index, pointer arithmetic
/// scaled by the struct's size (`param_1 + 1`), a comparison or an argument.
/// The cast costs the compiler nothing. A parameter the body writes or takes
/// the address of cannot be a cast; it is read through a local of the struct
/// type initialised from it, which the uses name instead.
fn cast_uses(text: &str, name: &str, structure: &str) -> String {
    let bytes = text.as_bytes();
    let uses: Vec<usize> = text
        .match_indices(name)
        .map(|(at, _)| at)
        .filter(|&at| {
            (at == 0 || !(is_word_byte(bytes[at - 1]) || bytes[at - 1] == b'.'))
                && bytes.get(at + name.len()).is_none_or(|b| !is_word_byte(*b))
        })
        .collect();
    if uses.is_empty() {
        return text.to_string();
    }
    let written = uses.iter().any(|&at| is_written(text, at, at + name.len()));
    let replacement = if written { format!("{name}_s") } else { format!("(({structure} *){name})") };
    let mut out = String::with_capacity(text.len() + 16 * uses.len());
    let mut last = 0;
    for at in uses {
        out.push_str(&text[last..at]);
        out.push_str(&replacement);
        last = at + name.len();
    }
    out.push_str(&text[last..]);
    if written {
        // After the opening brace, before the body's own declarations.
        out.insert_str(1, &format!("\n  {structure} *{name}_s = ({structure} *){name};"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use romwright_model::{FuncParam, FuncProto};

    fn doc(parameter: &str, structure: &str) -> DecompDoc {
        let ty = DecompType {
            name: None,
            id: None,
            size: Some(4),
            metatype: Some("ptr".into()),
            element_count: None,
            target: Some(Box::new(DecompType {
                name: Some(structure.into()),
                id: None,
                size: Some(16),
                metatype: Some("struct".into()),
                element_count: None,
                target: None,
                prototype: None,
            })),
            prototype: None,
        };
        let void = DecompType {
            name: Some("void".into()),
            id: None,
            size: None,
            metatype: Some("void".into()),
            element_count: None,
            target: None,
            prototype: None,
        };
        DecompDoc {
            tokens: Vec::new(),
            prototype: Some(FuncProto {
                calling_convention: String::new(),
                return_type: void,
                parameters: vec![FuncParam { ordinal: 0, name: parameter.into(), data_type: ty }],
                variadic: false,
                no_return: false,
                parameter_source: None,
            }),
            call_prototypes: Default::default(),
            call_targets: Default::default(),
            jump_tables: None,
            address: romwright_model::Address::ram(0x1000),
            revision: 0,
            storage: Vec::new(),
            function_ir: None,
        }
    }

    #[test]
    fn a_declaration_that_does_not_name_the_struct_gets_the_cast_at_each_use() {
        let doc = doc("param_1", "fn_00001000_arg0");
        let body = "void f(void *param_1, int param_10)\n{\n  param_1->field_0x4 = param_10->x;\n  \
                    g(param_1);\n  h(&param_1->field_0x8, param_1 [2].field_0x0);\n  \
                    q = (short *)(param_1 + 1);\n}\n"
            .to_string();
        let cast = cast_struct_params(&doc, body);
        assert!(cast.contains("((fn_00001000_arg0 *)param_1)->field_0x4 = param_10->x;"), "{cast}");
        assert!(cast.contains("g(((fn_00001000_arg0 *)param_1));"), "{cast}");
        assert!(cast.contains("&((fn_00001000_arg0 *)param_1)->field_0x8"), "{cast}");
        assert!(cast.contains("((fn_00001000_arg0 *)param_1) [2].field_0x0"), "{cast}");
        // Pointer arithmetic is scaled by the struct's size: on a `void *` it would be a byte.
        assert!(cast.contains("(short *)(((fn_00001000_arg0 *)param_1) + 1)"), "{cast}");
        // The signature is not rewritten, and `param_10` is another name.
        assert!(cast.starts_with("void f(void *param_1, int param_10)"));
    }

    #[test]
    fn a_parameter_the_body_writes_is_read_through_a_typed_local() {
        let doc = doc("param_1", "fn_00001000_arg0");
        let body = "void f(void *param_1)\n{\n  int x;\n  param_1 = param_1 + 1;\n  x = param_1->field_0x4;\n}\n".to_string();
        let cast = cast_struct_params(&doc, body);
        assert!(cast.contains("{\n  fn_00001000_arg0 *param_1_s = (fn_00001000_arg0 *)param_1;\n  int x;"), "{cast}");
        assert!(cast.contains("param_1_s = param_1_s + 1;"), "{cast}");
        assert!(cast.contains("x = param_1_s->field_0x4;"), "{cast}");
        // Taking the address is a write too.
        let cast = cast_struct_params(&doc, "void f(void *param_1)\n{\n  g(&param_1);\n}\n".to_string());
        assert!(cast.contains("g(&param_1_s);"), "{cast}");
        // A bit-and of two operands is not.
        let cast = cast_struct_params(&doc, "void f(void *param_1)\n{\n  y = x & param_1;\n}\n".to_string());
        assert!(cast.contains("y = x & ((fn_00001000_arg0 *)param_1);"), "{cast}");
    }

    #[test]
    fn a_pointee_the_worker_reports_as_a_bare_typeref_is_still_a_struct() {
        // `<typeref name id>` carries no metatype (`romwright-worker/src/prototype.rs`).
        let mut doc = doc("param_1", "fn_00001000_arg0");
        doc.prototype.as_mut().unwrap().parameters[0].data_type.target.as_mut().unwrap().metatype = None;
        let body = "void f(void *param_1)\n{\n  param_1->field_0x4 = 1;\n}\n".to_string();
        assert!(cast_struct_params(&doc, body).contains("((fn_00001000_arg0 *)param_1)->field_0x4"));
        // A name nobody makes is not assumed to be a struct.
        doc.prototype.as_mut().unwrap().parameters[0].data_type.target.as_mut().unwrap().name = Some("Foo".into());
        let body = "void f(void *param_1)\n{\n  g(param_1);\n}\n".to_string();
        assert_eq!(cast_struct_params(&doc, body.clone()), body);
    }

    #[test]
    fn a_signature_that_names_the_struct_needs_no_cast() {
        let doc = doc("param_1", "fn_00001000_arg0");
        let body = "void f(fn_00001000_arg0 *param_1)\n{\n  param_1->field_0x4 = 1;\n}\n".to_string();
        assert_eq!(cast_struct_params(&doc, body.clone()), body);
    }
}
