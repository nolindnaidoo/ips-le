//! YAML, by indentation.
//!
//! A stack of `(column, key)` reconstructs the dotted path: a key
//! indented further than the one above it is inside it, and one
//! indented the same or less closes everything at or below its own
//! column. That is the whole model, and it is the whole of YAML this
//! reader claims to understand.
//!
//! It attaches a coarser key than a real parser would for flow
//! mappings, anchors, merge keys and block scalars. That is the
//! deliberate limit: the address itself comes from the byte scan, so
//! the worst case here is a less precise locator, never a missed or a
//! misread address — which is why this is fifty lines instead of a
//! parser dependency.

use super::{KeySpan, lines};

pub(crate) fn keys(text: &str) -> Vec<KeySpan> {
    let mut stack: Vec<(usize, String)> = Vec::new();
    let mut spans = Vec::new();

    for (offset, line) in lines(text) {
        let content = strip_comment(line);
        let trimmed = content.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed == "-" {
            continue;
        }
        if trimmed.starts_with("---") || trimmed.starts_with("...") {
            stack.clear();
            continue;
        }

        // A sequence entry may hold a mapping of its own — `- addr: x`
        // — so the entry starts after the dash and its column is where
        // the entry starts, not where the dash does.
        let indent = content.len() - trimmed.len();
        let entry = trimmed.strip_prefix("- ").map_or(trimmed, str::trim_start);
        let column = indent + (trimmed.len() - entry.len());

        while stack.last().is_some_and(|(depth, _)| *depth >= column) {
            stack.pop();
        }

        let Some(separator) = key_separator(entry) else {
            // A bare sequence entry — `- 10.0.0.0/8` — belongs to the
            // key above it.
            if !stack.is_empty() {
                spans.push(KeySpan {
                    start: offset + column,
                    end: offset + line.len(),
                    path: path_of(&stack),
                });
            }
            continue;
        };

        let key = entry[..separator].trim().trim_matches(['"', '\'']);
        stack.push((column, key.to_string()));

        let value_at = column + separator + 1;
        if content[value_at.min(content.len())..].trim().is_empty() {
            continue; // a parent key, not a value
        }
        spans.push(KeySpan {
            start: offset + value_at,
            end: offset + line.len(),
            path: path_of(&stack),
        });
    }
    spans
}

fn path_of(stack: &[(usize, String)]) -> String {
    stack
        .iter()
        .map(|(_, key)| key.as_str())
        .collect::<Vec<&str>>()
        .join(".")
}

/// The `:` that ends a key: one followed by a space or by end of line.
///
/// The distinction the whole reader turns on. `upstream: 2001:db8::1`
/// has four colons and only the first is a key separator, and a search
/// for "the first colon" would cut an IPv6 address in half.
fn key_separator(entry: &str) -> Option<usize> {
    let bytes = entry.as_bytes();
    (0..bytes.len())
        .find(|index| bytes[*index] == b':' && bytes.get(index + 1).is_none_or(|n| *n == b' '))
}

/// A `#` that starts a comment: one at the start of a line or preceded
/// by a space. `http://x#y` is not a comment.
fn strip_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    line.char_indices()
        .find(|(index, character)| *character == '#' && (*index == 0 || bytes[index - 1] == b' '))
        .map_or(line, |(index, _)| &line[..index])
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
    fn a_nested_key_becomes_a_dotted_path() {
        let text = "server:\n  bind: 10.0.0.5\n";
        assert_eq!(at(text, "10.0.0.5").as_deref(), Some("server.bind"));
    }

    #[test]
    fn a_top_level_key_stands_alone() {
        assert_eq!(at("bind: 10.0.0.5\n", "10.0.0.5").as_deref(), Some("bind"));
    }

    /// The reason `key_separator` is not `find(':')`.
    #[test]
    fn an_ipv6_value_is_not_cut_in_half_by_its_own_colons() {
        let text = "dns:\n  upstream: 2001:db8::1\n";
        assert_eq!(at(text, "2001:db8::1").as_deref(), Some("dns.upstream"));
    }

    #[test]
    fn dedenting_closes_the_keys_it_left() {
        let text = "a:\n  b:\n    c: 10.0.0.1\nd: 10.0.0.2\n";
        assert_eq!(at(text, "10.0.0.1").as_deref(), Some("a.b.c"));
        assert_eq!(at(text, "10.0.0.2").as_deref(), Some("d"));
    }

    /// An allow-list is a sequence, and every entry keeps the key.
    #[test]
    fn a_sequence_entry_belongs_to_the_key_above_it() {
        let text = "allow:\n  - 10.0.0.0/8\n  - 192.168.0.0/16\n";
        assert_eq!(at(text, "10.0.0.0/8").as_deref(), Some("allow"));
        assert_eq!(at(text, "192.168.0.0/16").as_deref(), Some("allow"));
    }

    /// The case the column bookkeeping exists for: a sibling key inside
    /// a sequence entry must not nest under the entry's first key.
    #[test]
    fn a_mapping_inside_a_sequence_keeps_its_own_key() {
        let text = "peers:\n  - addr: 10.0.0.2\n    gateway: 10.0.0.1\n";
        assert_eq!(at(text, "10.0.0.2").as_deref(), Some("peers.addr"));
        assert_eq!(at(text, "10.0.0.1").as_deref(), Some("peers.gateway"));
    }

    #[test]
    fn a_document_separator_resets_the_stack() {
        let text = "a:\n  b: 10.0.0.1\n---\nc: 10.0.0.2\n";
        assert_eq!(at(text, "10.0.0.2").as_deref(), Some("c"));
    }

    #[test]
    fn a_comment_is_not_a_value() {
        assert!(keys("# bind: 10.0.0.5\n").is_empty());
        assert_eq!(strip_comment("a: b # c"), "a: b ");
        assert_eq!(strip_comment("a: http://x#y"), "a: http://x#y");
    }

    /// A key with nothing after it is a parent, not a value.
    #[test]
    fn a_key_with_no_value_names_no_span() {
        assert!(keys("server:\n").is_empty());
    }
}
