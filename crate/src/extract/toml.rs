//! TOML, line by line.
//!
//! A table header sets the prefix and `key = value` names a value —
//! the same shape as INI, plus the one thing that is not: an array can
//! run over many lines, and an allow-list of CIDR blocks is written
//! exactly that way. So a key stays open while its brackets are
//! unbalanced, and every line under it carries it.
//!
//! Nothing here understands TOML's grammar. It does not need to: a key
//! path is a locator, and the address itself is read from the bytes by
//! the scan whether this reader followed the document or not.

use super::{KeySpan, dotted, lines};

pub(crate) fn keys(text: &str) -> Vec<KeySpan> {
    let mut table = String::new();
    let mut open: Option<(String, isize)> = None;
    let mut spans = Vec::new();

    for (offset, line) in lines(text) {
        let content = strip_comment(line);
        let trimmed = content.trim();

        // A continuation of a multi-line array: the whole line belongs
        // to the key that opened it.
        if let Some((path, depth)) = open.take() {
            spans.push(KeySpan {
                start: offset,
                end: offset + content.len(),
                path: path.clone(),
            });
            let depth = depth + bracket_depth(content);
            if depth > 0 {
                open = Some((path, depth));
            }
            continue;
        }

        if trimmed.is_empty() {
            continue;
        }
        if let Some(name) = table_header(trimmed) {
            table = name;
            continue;
        }

        let Some(separator) = content.find('=') else {
            continue;
        };
        let key = content[..separator].trim();
        if key.is_empty() {
            continue;
        }
        let path = dotted(&table, key);
        spans.push(KeySpan {
            start: offset + separator + 1,
            end: offset + content.len(),
            path: path.clone(),
        });

        let depth = bracket_depth(&content[separator..]);
        if depth > 0 {
            open = Some((path, depth));
        }
    }
    spans
}

/// `[table]` and `[[array-of-tables]]`, both flattened to the dotted
/// name. The double brackets carry an index this does not track — one
/// path for every element of an array of tables is the honest limit of
/// a line reader, and SPEC.md says so.
fn table_header(trimmed: &str) -> Option<String> {
    let inner = trimmed.strip_prefix('[')?.strip_suffix(']')?;
    let inner = inner
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(inner);
    Some(inner.trim().to_string())
}

/// TOML ends a value at any `#` outside a quoted string — a bare value
/// cannot hold one, so unlike the other dialects there is nothing to
/// protect by requiring whitespace first.
fn strip_comment(line: &str) -> &str {
    super::strip_comment(line, &['#'], false)
}

fn bracket_depth(text: &str) -> isize {
    text.bytes().fold(0, |depth, byte| match byte {
        b'[' => depth + 1,
        b']' => depth - 1,
        _ => depth,
    })
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
    fn a_table_prefixes_its_keys() {
        let text = "[server]\nbind = \"10.0.0.5\"\n";
        assert_eq!(at(text, "10.0.0.5").as_deref(), Some("server.bind"));
    }

    #[test]
    fn a_top_level_key_stands_alone() {
        assert_eq!(
            at("gateway = \"10.0.0.1\"\n", "10.0.0.1").as_deref(),
            Some("gateway")
        );
    }

    /// The reason this reader is not the INI one: an allow-list is
    /// written across lines, and every entry has to keep its key.
    #[test]
    fn a_multi_line_array_keeps_its_key_on_every_line() {
        let text = "[firewall]\nallow = [\n  \"10.0.0.0/8\",\n  \"192.168.0.0/16\",\n]\nnext = 1\n";
        assert_eq!(at(text, "10.0.0.0/8").as_deref(), Some("firewall.allow"));
        assert_eq!(
            at(text, "192.168.0.0/16").as_deref(),
            Some("firewall.allow")
        );
    }

    /// And it has to close again, or every line after it inherits a key
    /// it has nothing to do with.
    #[test]
    fn a_closed_array_does_not_leak_into_the_next_key() {
        let text = "allow = [\n  \"10.0.0.0/8\",\n]\nbind = \"192.168.1.1\"\n";
        assert_eq!(at(text, "192.168.1.1").as_deref(), Some("bind"));
    }

    #[test]
    fn a_single_line_array_does_not_open_anything() {
        let text = "allow = [\"10.0.0.0/8\"]\nbind = \"192.168.1.1\"\n";
        assert_eq!(at(text, "10.0.0.0/8").as_deref(), Some("allow"));
        assert_eq!(at(text, "192.168.1.1").as_deref(), Some("bind"));
    }

    #[test]
    fn an_array_of_tables_flattens_to_its_name() {
        let text = "[[peers]]\naddr = \"10.0.0.2\"\n";
        assert_eq!(at(text, "10.0.0.2").as_deref(), Some("peers.addr"));
    }

    /// A `#` inside a string is part of the value, which is the whole
    /// reason quoting exists.
    #[test]
    fn a_hash_inside_a_string_is_not_a_comment() {
        assert_eq!(strip_comment(r#"a = "x#y" # real"#), r#"a = "x#y" "#);
        assert_eq!(strip_comment("a = 1"), "a = 1");
    }

    #[test]
    fn a_commented_line_names_nothing() {
        assert!(keys("# bind = \"10.0.0.5\"\n").is_empty());
    }

    /// A line with no `=`, a `=` with no key before it, and a bracket
    /// that never closes. None of them is a key, and none of them is an
    /// error either: the byte scan already ran over the same line.
    #[test]
    fn a_line_that_names_no_key_yields_no_span() {
        assert!(keys("just some prose 10.0.0.1\n").is_empty());
        assert!(keys("= \"10.0.0.1\"\n").is_empty());
        assert!(keys("[unclosed 10.0.0.1\n").is_empty());
        assert_eq!(table_header("[unclosed"), None);
        assert_eq!(table_header("bind = 1"), None);
    }
}
