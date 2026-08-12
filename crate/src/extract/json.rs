//! JSON and JSONC, by the parse tree.
//!
//! The one format here read by a parser rather than line by line, for
//! two reasons a line reader cannot answer: a minified document is one
//! line, and JSON nests arbitrarily deep. Both make a column-based key
//! reader useless exactly where the key path is most wanted.
//!
//! Comments and trailing commas are accepted — a `.jsonc` config, a
//! `tsconfig`, a Kubernetes manifest someone annotated — because
//! refusing them would drop the key paths for the documents most likely
//! to hold an allow-list.
//!
//! **A document that does not parse still gets its byte scan.** The
//! addresses are reported; only the key paths are missing, and
//! `parse_error` says so as a warning. Reporting nothing for a broken
//! config would hide exactly the file most likely to be wrong.

use jsonc_parser::ast::{Object, Value};
use jsonc_parser::common::Ranged;
use jsonc_parser::{CollectOptions, ParseOptions, parse_to_ast};

use super::KeySpan;

fn options() -> ParseOptions {
    ParseOptions {
        allow_comments: true,
        allow_trailing_commas: true,
        allow_loose_object_property_names: false,
        allow_missing_commas: false,
        allow_single_quoted_strings: false,
        allow_hexadecimal_numbers: false,
        allow_unary_plus_numbers: false,
    }
}

pub(crate) fn keys(text: &str) -> Vec<KeySpan> {
    let Ok(result) = parse_to_ast(text, &CollectOptions::default(), &options()) else {
        return Vec::new();
    };
    let Some(root) = result.value else {
        return Vec::new();
    };
    let mut spans = Vec::new();
    visit(&root, &mut Vec::new(), &mut spans);
    spans
}

pub(crate) fn parse_error(text: &str) -> Option<String> {
    if text.trim().is_empty() {
        return None;
    }
    parse_to_ast(text, &CollectOptions::default(), &options())
        .err()
        .map(|error| format!("could not read this as JSON, so no key paths are reported: {error}"))
}

/// Leaf values only, so the spans never overlap and a lookup can be a
/// binary search. A container's own range would enclose every child's.
fn visit(value: &Value, path: &mut Vec<String>, spans: &mut Vec<KeySpan>) {
    match value {
        Value::Array(array) => {
            for (index, element) in array.elements.iter().enumerate() {
                path.push(format!("[{index}]"));
                visit(element, path, spans);
                path.pop();
            }
        }
        Value::Object(object) => visit_object(object, path, spans),
        leaf => spans.push(KeySpan {
            start: leaf.range().start,
            end: leaf.range().end,
            path: path.join("."),
        }),
    }
}

fn visit_object(object: &Object, path: &mut Vec<String>, spans: &mut Vec<KeySpan>) {
    for property in &object.properties {
        path.push(property.name.as_str().to_string());
        visit(&property.value, path, spans);
        path.pop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str, needle: &str) -> Option<String> {
        let at = text.find(needle).expect("the needle is in the text");
        keys(text)
            .into_iter()
            .find(|span| span.start <= at && at < span.end)
            .map(|span| span.path)
    }

    #[test]
    fn a_nested_value_becomes_a_dotted_path() {
        let text = r#"{"server":{"bind":"10.0.0.5"}}"#;
        assert_eq!(at(text, "10.0.0.5").as_deref(), Some("server.bind"));
    }

    #[test]
    fn an_array_element_is_named_by_its_index() {
        let text = r#"{"allow":["10.0.0.0/8","192.168.0.0/16"]}"#;
        assert_eq!(at(text, "10.0.0.0/8").as_deref(), Some("allow.[0]"));
        assert_eq!(at(text, "192.168.0.0/16").as_deref(), Some("allow.[1]"));
    }

    /// The case a line reader cannot serve, and the reason this one
    /// format carries a parser.
    #[test]
    fn a_minified_document_still_has_key_paths() {
        let text = r#"{"a":{"b":{"c":"2001:db8::1"}}}"#;
        assert_eq!(at(text, "2001:db8::1").as_deref(), Some("a.b.c"));
    }

    #[test]
    fn a_key_is_not_inside_its_own_span() {
        assert_eq!(at(r#"{"10.0.0.1":"x"}"#, "10.0.0.1"), None);
    }

    /// A config someone annotated is still a config.
    #[test]
    fn comments_and_trailing_commas_are_read() {
        let text = "{\n  // the gateway\n  \"bind\": \"10.0.0.5\",\n}";
        assert_eq!(at(text, "10.0.0.5").as_deref(), Some("bind"));
        assert!(parse_error(text).is_none());
    }

    /// A broken document loses its key paths and nothing else — the
    /// addresses still come from the byte scan.
    #[test]
    fn a_broken_document_yields_no_keys_and_says_why() {
        assert!(keys("{not json").is_empty());
        let error = parse_error("{not json").expect("a reason");
        assert!(error.contains("key paths"), "{error}");
    }

    /// An empty document parses and holds no value at all, which is the
    /// one shape that is neither a tree to walk nor a failure to report.
    #[test]
    fn an_empty_document_is_not_an_error() {
        assert!(parse_error("").is_none());
        assert!(parse_error("   \n ").is_none());
        assert!(keys("").is_empty());
        assert!(keys("  \n\t ").is_empty());
        assert!(keys("// only a comment\n").is_empty());
    }

    /// Spans must not overlap, or the binary search in `locate.rs`
    /// returns whichever one it happens to land on.
    #[test]
    fn spans_are_disjoint_and_ordered() {
        let text = r#"{"a":{"b":"1","c":["2","3"]},"d":"4"}"#;
        let spans = keys(text);
        assert_eq!(spans.len(), 4);
        for pair in spans.windows(2) {
            assert!(pair[0].end <= pair[1].start, "{pair:?}");
        }
    }
}
