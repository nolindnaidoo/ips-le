//! INI and `.properties`, line by line.
//!
//! A section header sets the prefix; `key = value` and `key: value`
//! both name a value. Nothing else is read — an INI dialect has no
//! nesting to reconstruct, so there is no ambiguity to resolve and no
//! reason for a parser.

use super::{KeySpan, dotted, lines};

pub(crate) fn keys(text: &str) -> Vec<KeySpan> {
    let mut section = String::new();
    let mut spans = Vec::new();

    for (offset, line) in lines(text) {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with([';', '#']) {
            continue;
        }
        if let Some(name) = trimmed.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
            section = name.trim().to_string();
            continue;
        }
        if let Some(span) = span(offset, line, &section) {
            spans.push(span);
        }
    }
    spans
}

fn span(offset: usize, line: &str, section: &str) -> Option<KeySpan> {
    let separator = line.find(['=', ':'])?;
    let key = line[..separator].trim();
    if key.is_empty() {
        return None;
    }
    Some(KeySpan {
        start: offset + separator + 1,
        end: offset + line.len(),
        path: dotted(section, key),
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
    fn a_section_prefixes_its_keys() {
        let text = "[server]\nbind = 10.0.0.5\n";
        assert_eq!(at(text, "10.0.0.5").as_deref(), Some("server.bind"));
    }

    #[test]
    fn a_key_outside_a_section_stands_alone() {
        assert_eq!(at("bind = 10.0.0.5\n", "10.0.0.5").as_deref(), Some("bind"));
    }

    #[test]
    fn a_colon_separates_as_well_as_an_equals() {
        assert_eq!(at("host: 10.0.0.5\n", "10.0.0.5").as_deref(), Some("host"));
    }

    /// The trap this format sets: an IPv6 value has colons in it, and
    /// the separator is the **first** one.
    #[test]
    fn an_ipv6_value_does_not_split_its_own_key() {
        let text = "[dns]\nupstream = 2001:db8::1\n";
        assert_eq!(at(text, "2001:db8::1").as_deref(), Some("dns.upstream"));
    }

    #[test]
    fn comments_in_both_dialects_are_skipped() {
        assert!(keys("; a = 10.0.0.1\n# b = 10.0.0.2\n").is_empty());
    }

    #[test]
    fn a_section_header_is_not_a_value() {
        assert_eq!(at("[10.0.0.1]\na = b\n", "10.0.0.1"), None);
    }

    /// A line with no separator, and a separator with no key before it,
    /// both name nothing. The addresses on them are still scanned — the
    /// reader only ever costs a key path, never a finding.
    #[test]
    fn a_line_that_names_no_key_yields_no_span() {
        assert!(keys("just some prose 10.0.0.1\n").is_empty());
        assert!(keys("= 10.0.0.1\n").is_empty());
        assert!(keys("   : 10.0.0.1\n").is_empty());
    }
}
