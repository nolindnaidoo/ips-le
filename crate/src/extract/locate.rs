//! Joining the three halves: what the scan found, where it is, and what
//! the format calls it.
//!
//! This is also where **context** is assembled, which is what makes the
//! ambiguity refusals conditional rather than constant. `10.0.1` under
//! `"version"` is a version and produces nothing; the same three groups
//! in a log line produce `ambiguous_version`. Neither answer is
//! available from the token alone, which is why the policy layer takes
//! a `Context` and this module builds it.

use super::policy::{self, Context, Reading};
use super::position::PositionIndex;
use super::{Found, KeySpan, csv, dotenv, format, ini, json, log, scanner, toml, yaml};

/// Every address and every refusal in a document, in document order.
pub(crate) fn find(text: &str, format_key: &str) -> Vec<Found> {
    let spans = keys(text, format_key);
    let index = PositionIndex::new(text);

    scanner::candidates(text)
        .into_iter()
        .filter_map(|candidate| {
            let key = key_at(&spans, candidate.offset);
            // The only evidence outside the token. `v1.2.3.4` needs
            // none: the scanner already refuses a run glued to a name.
            let context = Context::from_key(key);
            let reading = policy::read(candidate.text, context)?;
            let position = index.at(candidate.offset);
            Some(match reading {
                Reading::Address {
                    kind,
                    normalized,
                    class,
                    block,
                } => Found {
                    kind: Some(kind),
                    text: candidate.text.to_string(),
                    line: position.line,
                    column: position.column,
                    key: key.map(str::to_string),
                    normalized: Some(normalized),
                    class: Some(class),
                    cidr: block,
                    refused: None,
                },
                Reading::Refused { kind, refusal } => Found {
                    kind,
                    text: candidate.text.to_string(),
                    line: position.line,
                    column: position.column,
                    key: key.map(str::to_string),
                    normalized: None,
                    class: None,
                    cidr: None,
                    refused: Some(refusal),
                },
            })
        })
        .collect()
}

/// Which format reader supplies key paths.
///
/// The fallback supplies none, and that costs nothing: the scan already
/// ran over the same bytes. This is the difference between a format
/// this crate knows and one it does not — never whether an address is
/// found.
fn keys(text: &str, format_key: &str) -> Vec<KeySpan> {
    match format::canonical(format_key) {
        "json" => json::keys(text),
        "yaml" => yaml::keys(text),
        "toml" => toml::keys(text),
        "ini" => ini::keys(text),
        "env" => dotenv::keys(text),
        "csv" => csv::keys(text, csv::COMMA),
        "tsv" => csv::keys(text, csv::TAB),
        "log" => log::keys(text),
        _ => Vec::new(),
    }
}

/// The key naming the region an offset falls in.
///
/// Spans are leaf values, so they never overlap and never nest — which
/// is what lets this be a binary search instead of a walk, and is why a
/// log file with a hundred thousand pairs stays linear overall.
fn key_at(spans: &[KeySpan], offset: usize) -> Option<&str> {
    let candidate = spans
        .partition_point(|span| span.start <= offset)
        .checked_sub(1)?;
    let span = &spans[candidate];
    (offset < span.end).then_some(span.path.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::{Class, Kind, policy::Reason};

    fn found(text: &str, format: &str) -> Vec<Found> {
        find(text, format)
    }

    fn one(text: &str, format: &str) -> Found {
        let mut all = found(text, format);
        assert_eq!(all.len(), 1, "{text} produced {all:?}");
        all.remove(0)
    }

    #[test]
    fn an_address_carries_its_position_and_its_key() {
        let one = one("server:\n  bind: 10.0.0.5\n", "yaml");
        assert_eq!(one.kind, Some(Kind::Ipv4));
        assert_eq!(one.text, "10.0.0.5");
        assert_eq!(one.line, 2);
        assert_eq!(one.column, 9);
        assert_eq!(one.key.as_deref(), Some("server.bind"));
        assert_eq!(one.normalized.as_deref(), Some("10.0.0.5"));
        assert_eq!(one.class, Some(Class::Private));
    }

    /// Order is document order, whatever the format's own structure is.
    #[test]
    fn findings_come_back_in_document_order() {
        let text = "a: 10.0.0.1\nb: 10.0.0.2\nc: 10.0.0.3\n";
        let texts: Vec<String> = found(text, "yaml").into_iter().map(|f| f.text).collect();
        assert_eq!(texts, ["10.0.0.1", "10.0.0.2", "10.0.0.3"]);
    }

    /// The conditional refusal, both ways round, in one test — this is
    /// the behaviour the `Context` type exists for.
    #[test]
    fn a_dotted_triple_refuses_or_disappears_depending_on_its_key() {
        let refused = one("build: 10.0.1\n", "yaml");
        assert_eq!(
            refused.refused.expect("a refusal").reason,
            Reason::AmbiguousVersion
        );
        assert!(found("version: 10.0.1\n", "yaml").is_empty());
        assert!(found("app_version: 10.0.1\n", "yaml").is_empty());
    }

    /// A changelog has no keys at all, so the scanner's boundary rule
    /// is the only thing standing between a release note and a page of
    /// refusals.
    #[test]
    fn a_version_glued_to_a_name_never_reaches_the_policy_layer() {
        assert!(found("released v1.2.3.4 today", "unknown").is_empty());
        assert!(found("upgraded to v10.0.1", "unknown").is_empty());
        // A bare dotted quad is still an address.
        assert_eq!(one("saw 1.2.3.4 once", "unknown").kind, Some(Kind::Ipv4));
    }

    /// The integer form needs a key, and the key comes from the format
    /// reader — so the two layers have to meet correctly for it to fire
    /// at all.
    #[test]
    fn an_address_key_reaches_the_policy_layer() {
        let one = one("BIND_IP=2130706433\n", "env");
        let refusal = one.refused.expect("a refusal");
        assert_eq!(refusal.reason, Reason::IntegerForm);
        assert_eq!(one.key.as_deref(), Some("BIND_IP"));
        assert!(found("TIMEOUT=2130706433\n", "env").is_empty());
    }

    #[test]
    fn an_unknown_format_still_finds_addresses_and_reports_no_key() {
        let one = one("allow 2001:db8::1 through", "unknown");
        assert_eq!(one.normalized.as_deref(), Some("2001:db8::1"));
        assert_eq!(one.key, None);
    }

    /// An address outside any value region — in a comment, in a key —
    /// is found and unnamed.
    #[test]
    fn an_address_outside_a_value_has_no_key() {
        let one = one("# fallback 10.0.0.9\n", "yaml");
        assert_eq!(one.text, "10.0.0.9");
        assert_eq!(one.key, None);
    }

    /// SPEC.md promises that an address in a comment is reported with no
    /// key, and `Found::key` promises null rather than a guess. A
    /// **trailing** comment used to hand its address the key beside it,
    /// so a config binding to 10.0.0.5 was reported as binding to
    /// 10.0.0.9 as well — a name attached to an address the file does
    /// not use, which is the false positive an allow-list review is
    /// least able to afford.
    #[test]
    fn an_address_in_a_trailing_comment_has_no_key() {
        for (format, text) in [
            ("yaml", "bind: 10.0.0.5 # fallback 10.0.0.9\n"),
            ("toml", "bind = \"10.0.0.5\" # fallback 10.0.0.9\n"),
            ("ini", "bind = 10.0.0.5 ; fallback 10.0.0.9\n"),
            ("ini", "bind = 10.0.0.5 # fallback 10.0.0.9\n"),
            ("env", "BIND=10.0.0.5 # fallback 10.0.0.9\n"),
        ] {
            let all = found(text, format);
            assert_eq!(all.len(), 2, "{format}: {all:?}");
            assert!(all[0].key.is_some(), "{format}: the value lost its key");
            assert_eq!(all[1].key, None, "{format}: the comment kept a key");
        }
    }

    /// The other half, and the reason the strip has to know about
    /// quotes: a marker inside a quoted value is part of the value.
    /// Cutting there would drop a real address's key — and on a bare
    /// `#` in a URL or a password, drop the address's key for nothing.
    #[test]
    fn a_comment_marker_inside_a_value_is_not_a_comment() {
        for (format, text) in [
            ("yaml", "bind: \"10.0.0.5 # 10.0.0.9\"\n"),
            ("toml", "bind = \"10.0.0.5 # 10.0.0.9\"\n"),
            ("ini", "bind = \"10.0.0.5 ; 10.0.0.9\"\n"),
            ("env", "BIND=\"10.0.0.5 # 10.0.0.9\"\n"),
            // No whitespace before the marker: not a comment in any of
            // these dialects.
            ("yaml", "bind: 10.0.0.5#10.0.0.9\n"),
            ("env", "BIND=10.0.0.5#10.0.0.9\n"),
        ] {
            let all = found(text, format);
            assert_eq!(all.len(), 2, "{format}: {all:?}");
            assert!(
                all[1].key.is_some(),
                "{format}: a value was cut at its own marker"
            );
        }
    }

    #[test]
    fn a_key_lookup_lands_inside_the_span_and_nowhere_else() {
        let spans = vec![
            KeySpan {
                start: 5,
                end: 10,
                path: "a".into(),
            },
            KeySpan {
                start: 20,
                end: 25,
                path: "b".into(),
            },
        ];
        assert_eq!(key_at(&spans, 0), None);
        assert_eq!(key_at(&spans, 5), Some("a"));
        assert_eq!(key_at(&spans, 9), Some("a"));
        assert_eq!(key_at(&spans, 10), None);
        assert_eq!(key_at(&spans, 24), Some("b"));
        assert_eq!(key_at(&spans, 99), None);
        assert_eq!(key_at(&[], 3), None);
    }

    /// The whole promise, on the file type that matters most: a log
    /// line yields the address that connected, with the line it is on.
    #[test]
    fn a_log_line_yields_the_address_that_connected() {
        let text = "192.168.1.10 - - [12/Aug/2026:10:30:00 +0000] \"GET /x HTTP/1.1\" 200 512\n";
        let all = found(text, "log");
        assert_eq!(all.len(), 1, "{all:?}");
        assert_eq!(all[0].normalized.as_deref(), Some("192.168.1.10"));
        assert_eq!(all[0].line, 1);
        assert_eq!(all[0].column, 1);
    }
}
