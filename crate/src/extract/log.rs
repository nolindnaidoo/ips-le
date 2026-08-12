//! Log files — the format this crate was written for.
//!
//! Every other format here holds addresses that somebody typed. A log
//! holds the ones that actually connected, which is why "who talked to
//! this service" is answered here and nowhere else in the tree.
//!
//! A log line has no schema, so this reader claims only what a line
//! demonstrably carries:
//!
//! - **logfmt** — `remote_addr=10.0.0.1 status=200`. The key is the
//!   key.
//! - **JSON per line** — one object per line, read by `json.rs` and
//!   offset onto the line.
//!
//! Anything else — Apache combined, syslog, a stack trace — gets no key
//! path, and that is the honest answer: the address in
//! `192.168.1.10 - - [12/Aug/2026:10:30:00 +0000]` is in position one
//! of an unnamed format, and inventing a name for it would be this tool
//! claiming to know a schema it was never given. The line and column
//! are what a reader needs there, and those always come from the scan.

use super::{KeySpan, json, lines};

pub(crate) fn keys(text: &str) -> Vec<KeySpan> {
    let mut spans = Vec::new();
    for (offset, line) in lines(text) {
        let trimmed = line.trim_start();
        if trimmed.starts_with('{') {
            let lead = offset + (line.len() - trimmed.len());
            spans.extend(json::keys(trimmed).into_iter().map(|span| KeySpan {
                start: span.start + lead,
                end: span.end + lead,
                path: span.path,
            }));
            continue;
        }
        logfmt(offset, line, &mut spans);
    }
    spans
}

/// `key=value` pairs, values ending at whitespace or at a closing
/// quote.
///
/// A key is a run of name characters immediately before an `=`. That
/// requirement is what keeps a URL query string or a base64 blob from
/// producing a key for every `=` in it.
fn logfmt(offset: usize, line: &str, spans: &mut Vec<KeySpan>) {
    let bytes = line.as_bytes();
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] != b'=' {
            index += 1;
            continue;
        }
        let key_start = name_start(bytes, index);
        if key_start == index {
            index += 1;
            continue;
        }
        let (value_start, value_end) = value_range(bytes, index + 1);
        spans.push(KeySpan {
            start: offset + value_start,
            end: offset + value_end,
            path: line[key_start..index].to_string(),
        });
        index = value_end.max(index + 1);
    }
}

/// Walk back over the name characters before an `=`.
fn name_start(bytes: &[u8], equals: usize) -> usize {
    let mut start = equals;
    while start > 0 && is_name_byte(bytes[start - 1]) {
        start -= 1;
    }
    start
}

fn is_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
}

/// A quoted value ends at its closing quote; a bare one ends at the
/// next space.
fn value_range(bytes: &[u8], start: usize) -> (usize, usize) {
    if bytes.get(start) == Some(&b'"') {
        let mut end = start + 1;
        while end < bytes.len() && bytes[end] != b'"' {
            end += 1;
        }
        return (start + 1, end);
    }
    let mut end = start;
    while end < bytes.len() && !bytes[end].is_ascii_whitespace() {
        end += 1;
    }
    (start, end)
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
    fn a_logfmt_pair_names_its_value() {
        let text = "level=info remote_addr=10.0.0.1 status=200\n";
        assert_eq!(at(text, "10.0.0.1").as_deref(), Some("remote_addr"));
    }

    #[test]
    fn a_quoted_logfmt_value_ends_at_its_quote() {
        let text = "msg=\"from 10.0.0.1 ok\" next=1\n";
        assert_eq!(at(text, "10.0.0.1").as_deref(), Some("msg"));
    }

    /// The modern default, and it nests.
    #[test]
    fn a_json_line_is_read_as_json() {
        let text = "{\"req\":{\"ip\":\"10.0.0.1\"},\"status\":200}\n";
        assert_eq!(at(text, "10.0.0.1").as_deref(), Some("req.ip"));
    }

    #[test]
    fn a_json_line_keeps_its_offset_among_other_lines() {
        let text = "starting up\n{\"ip\":\"10.0.0.1\"}\n";
        assert_eq!(at(text, "10.0.0.1").as_deref(), Some("ip"));
    }

    /// An Apache line has no keys, and saying so is the point. The
    /// address is still scanned; it just has no name.
    #[test]
    fn an_apache_line_names_nothing_and_that_is_the_answer() {
        let text = "192.168.1.10 - - [12/Aug/2026:10:30:00 +0000] \"GET / HTTP/1.1\" 200 512\n";
        assert_eq!(at(text, "192.168.1.10"), None);
    }

    /// A `=` with nothing name-like before it is not a pair.
    #[test]
    fn a_bare_equals_is_not_a_key() {
        assert!(keys("=10.0.0.1\n").is_empty());
        assert!(keys("a b = c\n").is_empty());
    }

    #[test]
    fn several_pairs_on_one_line_keep_their_own_keys() {
        let text = "src=10.0.0.1 dst=10.0.0.2\n";
        assert_eq!(at(text, "10.0.0.1").as_deref(), Some("src"));
        assert_eq!(at(text, "10.0.0.2").as_deref(), Some("dst"));
    }
}
