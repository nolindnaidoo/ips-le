//! `.env`, line by line.
//!
//! The key is the whole path — these files are flat — and the value
//! region runs from after the `=` to the end of the line, quotes
//! included. Quotes are left in because the scan reads bytes: stripping
//! them would move every offset on the line for no gain.

use super::{KeySpan, lines};

pub(crate) fn keys(text: &str) -> Vec<KeySpan> {
    lines(text)
        .filter_map(|(offset, line)| span(offset, line))
        .collect()
}

fn span(offset: usize, line: &str) -> Option<KeySpan> {
    // A whole-line comment strips to nothing and falls out at the
    // emptiness guard below, so there is no second check for one.
    let line = super::strip_comment(line, &['#'], true);
    let trimmed = line.trim_start();
    if trimmed.is_empty() {
        return None;
    }
    let lead = line.len() - trimmed.len();
    let content = trimmed.strip_prefix("export ").unwrap_or(trimmed);
    let lead = lead + (trimmed.len() - content.len());

    let equals = content.find('=')?;
    let key = content[..equals].trim();
    if key.is_empty() {
        return None;
    }
    Some(KeySpan {
        start: offset + lead + equals + 1,
        end: offset + line.len(),
        path: key.to_string(),
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
    fn a_value_carries_its_key() {
        assert_eq!(
            at("DB_HOST=10.0.0.5\n", "10.0.0.5").as_deref(),
            Some("DB_HOST")
        );
    }

    #[test]
    fn an_export_prefix_is_not_part_of_the_key() {
        assert_eq!(
            at("export BIND_IP=0.0.0.0\n", "0.0.0.0").as_deref(),
            Some("BIND_IP")
        );
    }

    /// The key itself is outside the span. An address written as a key
    /// is still scanned; it just has no key path, which is the honest
    /// answer.
    #[test]
    fn the_key_is_not_inside_its_own_span() {
        assert_eq!(at("A_10_B=x\n", "10"), None);
    }

    #[test]
    fn comments_and_blank_lines_have_no_keys() {
        assert!(keys("# DB_HOST=10.0.0.5\n\n   \n").is_empty());
    }

    #[test]
    fn a_line_with_no_equals_has_no_key() {
        assert!(keys("just some text 10.0.0.1\n").is_empty());
    }

    /// An `=` with nothing before it names nothing. The address after it
    /// is still scanned; it just carries no key, which is the honest
    /// answer rather than an empty one.
    #[test]
    fn an_equals_with_no_key_before_it_names_nothing() {
        assert!(keys("=10.0.0.1\n").is_empty());
        assert!(keys("   =10.0.0.1\n").is_empty());
        assert!(keys("export =10.0.0.1\n").is_empty());
    }

    #[test]
    fn every_line_keeps_its_own_key() {
        let text = "A=1.1.1.1\nB=2.2.2.2\n";
        assert_eq!(at(text, "1.1.1.1").as_deref(), Some("A"));
        assert_eq!(at(text, "2.2.2.2").as_deref(), Some("B"));
    }
}
