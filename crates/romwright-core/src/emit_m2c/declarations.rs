//! Preserve asserted C declarators without pretending Ghidra's types retain qualifiers.
use super::{globals, is_c_ident};
use romwright_model::{Address, FactKind, PrototypeRow};
use std::cell::{OnceCell, RefCell};
use std::collections::HashMap;
use std::ops::Range;
use tree_sitter::{Node, Parser, Tree};

#[derive(Debug)]
struct Declaration {
    source: String,
    tree: OnceCell<Result<Tree, String>>,
}

/// Export-local, lazily parsed assertions. Unused assertions cannot break an export.
pub struct DeclaredPrototypes {
    declarations: HashMap<Address, Declaration>,
    parser: RefCell<Parser>,
}

impl std::fmt::Debug for DeclaredPrototypes {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeclaredPrototypes")
            .field("assertion_count", &self.declarations.len())
            .finish_non_exhaustive()
    }
}

impl DeclaredPrototypes {
    pub fn new(rows: impl IntoIterator<Item = PrototypeRow>) -> Self {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_c::LANGUAGE.into())
            .expect("bundled C grammar is compatible with the parser");
        let declarations = rows
            .into_iter()
            .filter(|row| {
                row.provenance.kind == FactKind::Asserted && !row.signature.trim().is_empty()
            })
            .map(|row| {
                let signature = row.signature.trim();
                let source = format!("{};", signature.strip_suffix(';').unwrap_or(signature));
                (
                    row.function,
                    Declaration {
                        source,
                        tree: OnceCell::new(),
                    },
                )
            })
            .collect();
        Self {
            declarations,
            parser: RefCell::new(parser),
        }
    }

    fn parse(&self, source: &str) -> Result<Tree, String> {
        self.parser
            .borrow_mut()
            .parse(source, None)
            .ok_or_else(|| "C declaration parsing did not finish".into())
    }

    pub(super) fn callee(&self, address: &Address, name: &str) -> Result<Option<String>, String> {
        self.render(address, name, None, &[])
    }

    pub(super) fn definition(&self, address: &Address, mut body: String) -> Result<String, String> {
        if !self.declarations.contains_key(address) {
            return Ok(body);
        }
        let tree = self.parse(&body)?;
        let root = tree.root_node();
        let mut cursor = root.walk();
        let functions: Vec<_> = root
            .named_children(&mut cursor)
            .filter(|node| node.kind() == "function_definition")
            .collect();
        let [function] = functions.as_slice() else {
            return Err("asserted prototype requires one generated function definition".into());
        };
        let declarator = function
            .child_by_field_name("declarator")
            .ok_or("generated function has no declarator")?;
        if declarator.has_error() {
            return Err("generated function declarator is not valid C".into());
        }
        let (function_declarator, identifier) = function_parts(declarator)?;
        let name = text(identifier, &body);
        let parameters = parameters(function_declarator, &body)?;
        let names: Vec<_> = parameters
            .iter()
            .map(|parameter| {
                parameter
                    .child_by_field_name("declarator")
                    .and_then(identifier_of)
                    .map(|node| text(node, &body).to_string())
                    .ok_or_else(|| "generated definition has an unnamed parameter".to_string())
            })
            .collect::<Result<_, _>>()?;
        let conventions = calling_conventions(*function, &body);
        let declaration = self
            .render(address, name, Some(&names), &conventions)?
            .ok_or("asserted prototype disappeared during export")?;
        let storage: Vec<_> = function
            .named_children(&mut function.walk())
            .filter(|node| node.kind() == "storage_class_specifier")
            .map(|node| text(node, &body))
            .collect();
        let prefix = if storage.is_empty() {
            String::new()
        } else {
            format!("{} ", storage.join(" "))
        };
        let block = function
            .child_by_field_name("body")
            .ok_or("generated function has no body")?;
        body.replace_range(
            function.start_byte()..block.start_byte(),
            &format!("{prefix}{declaration}\n\n"),
        );
        Ok(body)
    }

    fn render(
        &self,
        address: &Address,
        name: &str,
        parameter_names: Option<&[String]>,
        conventions: &[String],
    ) -> Result<Option<String>, String> {
        let Some(declaration) = self.declarations.get(address) else {
            return Ok(None);
        };
        if !is_c_ident(name) {
            return Err(format!(
                "asserted prototype needs a C function identifier, got {name:?}"
            ));
        }
        let tree = declaration
            .tree
            .get_or_init(|| self.parse(&declaration.source));
        let tree = tree.as_ref().map_err(Clone::clone)?;
        let root = tree.root_node();
        let mut cursor = root.walk();
        let nodes: Vec<_> = root
            .named_children(&mut cursor)
            .filter(|node| node.kind() != "comment")
            .collect();
        let [node] = nodes.as_slice() else {
            return Err("asserted prototype must contain exactly one declaration".into());
        };
        if root.has_error() || node.kind() != "declaration" {
            return Err("asserted prototype is not a complete C declaration".into());
        }
        let mut cursor = node.walk();
        let declarators: Vec<_> = node
            .children_by_field_name("declarator", &mut cursor)
            .collect();
        let [declarator] = declarators.as_slice() else {
            return Err("asserted prototype must declare exactly one function".into());
        };
        let (function, identifier) = function_parts(*declarator)?;
        let source = &declaration.source;
        let asserted_conventions = calling_conventions(*node, source);
        if !conventions.is_empty()
            && !asserted_conventions.is_empty()
            && conventions != asserted_conventions
        {
            return Err("asserted and generated calling conventions disagree".into());
        }
        let binding = if asserted_conventions.is_empty() && !conventions.is_empty() {
            format!("{} {name}", conventions.join(" "))
        } else {
            name.to_string()
        };
        let mut edits = vec![(identifier.byte_range(), binding)];
        if let Some(names) = parameter_names {
            let parameters = parameters(function, source)?;
            if parameters.len() != names.len() {
                return Err(format!(
                    "asserted prototype has {} fixed parameters, generated definition has {}",
                    parameters.len(),
                    names.len()
                ));
            }
            for (parameter, name) in parameters.into_iter().zip(names) {
                if !is_c_ident(name) {
                    return Err(format!(
                        "generated parameter needs a C identifier, got {name:?}"
                    ));
                }
                bind_parameter(parameter, name, &mut edits)?;
            }
        }
        // Linkage comes from the generated definition or the caller's `extern`,
        // not from a storage class incidentally accepted by the signature parser.
        for child in node.named_children(&mut node.walk()) {
            if child.kind() == "storage_class_specifier" {
                edits.push((child.byte_range(), String::new()));
            }
        }
        let mut pending = vec![*node];
        while let Some(current) = pending.pop() {
            if matches!(current.kind(), "type_identifier" | "primitive_type") {
                if let Some(primitive) = globals::primitive_name(text(current, source)) {
                    edits.push((current.byte_range(), primitive.to_string()));
                }
            }
            pending.extend(current.named_children(&mut current.walk()));
        }
        let mut rendered = text(*node, source).to_string();
        edits.sort_by_key(|(range, _)| (range.start, range.end));
        for (range, replacement) in edits.into_iter().rev() {
            rendered.replace_range(
                range.start - node.start_byte()..range.end - node.start_byte(),
                &replacement,
            );
        }
        Ok(Some(
            rendered
                .trim()
                .strip_suffix(';')
                .unwrap_or(rendered.trim())
                .trim()
                .to_string(),
        ))
    }
}

fn text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    &source[node.byte_range()]
}

fn nested_declarator(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("declarator").or_else(|| {
        matches!(
            node.kind(),
            "parenthesized_declarator" | "abstract_parenthesized_declarator"
        )
        .then(|| node.named_child(0))
        .flatten()
    })
}

fn identifier_of(mut node: Node<'_>) -> Option<Node<'_>> {
    for _ in 0..64 {
        if node.kind() == "identifier" {
            return Some(node);
        }
        node = nested_declarator(node)?;
    }
    None
}

fn function_parts(mut node: Node<'_>) -> Result<(Node<'_>, Node<'_>), String> {
    let mut function = None;
    let mut nearest_constructor = "";
    for _ in 0..64 {
        if node.kind() == "function_declarator" {
            function = Some(node);
        }
        if node.kind() == "identifier" {
            return function
                .filter(|_| nearest_constructor == "function_declarator")
                .map(|function| (function, node))
                .ok_or_else(|| "assertion does not declare a function".into());
        }
        if node.kind() != "parenthesized_declarator" {
            nearest_constructor = node.kind();
        }
        node = nested_declarator(node).ok_or("function declarator has no identifier")?;
    }
    Err("C declarator nesting exceeds the supported depth".into())
}

fn parameters<'tree>(function: Node<'tree>, source: &str) -> Result<Vec<Node<'tree>>, String> {
    let list = function
        .child_by_field_name("parameters")
        .ok_or("function has no parameter list")?;
    let mut parameters: Vec<_> = list
        .named_children(&mut list.walk())
        .filter(|node| node.kind() == "parameter_declaration")
        .collect();
    if parameters.len() == 1 && parameters[0].child_by_field_name("declarator").is_none() {
        let parameter = parameters[0];
        if parameter
            .child_by_field_name("type")
            .is_some_and(|ty| text(ty, source) == "void")
        {
            parameters.clear();
        }
    }
    Ok(parameters)
}

fn bind_parameter(
    parameter: Node<'_>,
    name: &str,
    edits: &mut Vec<(Range<usize>, String)>,
) -> Result<(), String> {
    let Some(mut declarator) = parameter.child_by_field_name("declarator") else {
        edits.push((
            parameter.end_byte()..parameter.end_byte(),
            format!(" {name}"),
        ));
        return Ok(());
    };
    for _ in 0..64 {
        if declarator.kind() == "identifier" {
            edits.push((declarator.byte_range(), name.to_string()));
            return Ok(());
        }
        if let Some(inner) = nested_declarator(declarator) {
            declarator = inner;
            continue;
        }
        let insertion = match declarator.kind() {
            "abstract_pointer_declarator" => declarator.end_byte(),
            "abstract_array_declarator" | "abstract_function_declarator" => declarator.start_byte(),
            _ => {
                return Err(format!(
                    "cannot bind unnamed C parameter {}",
                    declarator.kind()
                ))
            }
        };
        edits.push((insertion..insertion, format!(" {name}")));
        return Ok(());
    }
    Err("C parameter nesting exceeds the supported depth".into())
}

fn calling_conventions(node: Node<'_>, source: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = Some(node);
    for _ in 0..64 {
        let Some(node) = current else { break };
        for child in node.named_children(&mut node.walk()) {
            if child.kind() == "ms_call_modifier" {
                result.push(text(child, source).to_string());
            }
        }
        current = nested_declarator(node);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use romwright_model::FactProvenance;

    fn assertion(address: u64, signature: &str) -> PrototypeRow {
        PrototypeRow {
            function: Address::ram(address),
            signature: signature.into(),
            calling_convention: None,
            return_type: None,
            provenance: FactProvenance::default(),
        }
    }

    #[test]
    #[ignore = "requires gcc"]
    fn qualified_declarators_compile_with_their_authoritative_contract() {
        let declarations = DeclaredPrototypes::new([
            assertion(1, "uint stored(const byte *, int (* const)(const char *), const Text, int [static const 2])"),
            assertion(2, "int (*stored_factory(void))(const char *)"),
            assertion(3, "long stored_scalar(char)"),
            assertion(4, "void stored_sink(const volatile byte *, int (*)(const char *))"),
            assertion(99, "unused malformed prototype {"),
        ]);
        let function = declarations.definition(&Address::ram(1),
            "unsigned int recovered(unsigned char *data, int (*callback)(char *), char *handle, int *values) { handle[0] = 'Z'; return data[0] + callback(handle) + values[1]; }".into()).unwrap();
        let factory = declarations
            .definition(
                &Address::ram(2),
                "int (*factory(void))(char *) { return consume; }".into(),
            )
            .unwrap();
        let scalar = declarations
            .definition(
                &Address::ram(3),
                "long scalar(char value) { return value; }".into(),
            )
            .unwrap();
        let callee = declarations
            .callee(&Address::ram(4), "sink")
            .unwrap()
            .unwrap();
        let source = format!(
            r#"
typedef char *Text;
unsigned int recovered(const unsigned char *, int (*)(const char *), const Text, int [static const 2]);
int consume(const char *text) {{ return text[0]; }}
void sink(const volatile unsigned char *data, int (*callback)(const char *)) {{ (void)data; (void)callback; }}
extern {callee};
{function}
{factory}
{scalar}
int main(void) {{
    const unsigned char data[] = {{7}};
    char handle[] = "Q";
    int values[] = {{3, 5}};
    return recovered(data, consume, handle, values) != 102 ||
        handle[0] != 'Z' || factory()("R") != 82 || scalar(3) != 3;
}}
"#
        );
        let root = std::env::temp_dir().join(format!(
            "romwright-qualified-declarations-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let input = root.join("candidate.c");
        let output = root.join("candidate");
        std::fs::write(&input, &source).unwrap();
        let compiled = std::process::Command::new("gcc")
            .args(["-std=c11", "-Wall", "-Werror", "-O2"])
            .arg(&input)
            .arg("-o")
            .arg(&output)
            .output()
            .unwrap();
        assert!(
            compiled.status.success(),
            "{}\n{source}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        assert!(std::process::Command::new(&output)
            .status()
            .unwrap()
            .success());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn incompatible_assertions_fail_instead_of_losing_the_contract() {
        let declarations = DeclaredPrototypes::new([
            assertion(1, "int (*pointer)(const char *)"),
            assertion(2, "int function(const char *, int)"),
        ]);
        assert!(declarations.callee(&Address::ram(1), "pointer").is_err());
        assert!(declarations
            .definition(
                &Address::ram(2),
                "int function(char *value) { return value[0]; }".into()
            )
            .is_err());
    }
}
