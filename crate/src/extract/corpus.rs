//! The corpus, embedded and run as unit tests.
//!
//! Embedding it means `cargo test` on the published tarball runs every
//! case, so whoever installed this can check the RFC 5952 and refusal
//! claims in the README instead of trusting them.
//!
//! Four sections, and each one exists because a different thing could
//! silently break:
//!
//! - **normalization** — the RFC 5952 forms. These are pinned against
//!   the RFC rather than against this implementation, because the
//!   implementation is `std::net`'s `Display` and a standard library is
//!   exactly the kind of dependency whose behaviour changes without
//!   anyone here noticing.
//! - **classification** — one address per class, so the ten-value
//!   vocabulary cannot grow a value nothing checks or lose one nothing
//!   reaches.
//! - **ambiguity** — every case expects a refusal, by name. This is the
//!   section that fails if someone ever "improves" a refusal into an
//!   answer.
//! - **documents** — a real file per format, findings and key paths
//!   included.

/// One corpus document, by name. Panics on a name the corpus does not
/// carry — a test naming a file that is not there is a broken test, not
/// a runtime condition.
#[cfg_attr(not(test), expect(dead_code, reason = "the corpus is a test fixture"))]
pub(crate) fn document(name: &str) -> &'static str {
    match name {
        "network.json" => include_str!("../../fixtures/documents/network.json"),
        "network.yaml" => include_str!("../../fixtures/documents/network.yaml"),
        "network.toml" => include_str!("../../fixtures/documents/network.toml"),
        "network.ini" => include_str!("../../fixtures/documents/network.ini"),
        "network.env" => include_str!("../../fixtures/documents/network.env"),
        "network.csv" => include_str!("../../fixtures/documents/network.csv"),
        "access.log" => include_str!("../../fixtures/documents/access.log"),
        "ambiguous.txt" => include_str!("../../fixtures/documents/ambiguous.txt"),
        "normalization.txt" => include_str!("../../fixtures/documents/normalization.txt"),
        "classes.txt" => include_str!("../../fixtures/documents/classes.txt"),
        other => panic!("the corpus has no document named {other}"),
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::document;
    use crate::extract::policy::{Context, Reading, Reason, read};
    use crate::extract::{Class, Kind, find};

    const CORPUS: &str = include_str!("../../fixtures/extraction.json");

    #[derive(Debug, Deserialize)]
    struct Corpus {
        normalization: Vec<Normalization>,
        classification: Vec<Classification>,
        ambiguity: Vec<Ambiguity>,
        documents: Vec<Document>,
    }

    #[derive(Debug, Deserialize)]
    struct Normalization {
        input: String,
        expected: String,
        why: String,
    }

    #[derive(Debug, Deserialize)]
    struct Classification {
        input: String,
        kind: Kind,
        class: Class,
    }

    #[derive(Debug, Deserialize)]
    struct Ambiguity {
        input: String,
        reason: Reason,
        /// The key the token sits under, where the refusal depends on
        /// one.
        #[serde(default)]
        key: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    struct Document {
        name: String,
        file: String,
        format: String,
        expected: Vec<Expected>,
    }

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct Expected {
        text: String,
        line: usize,
        column: usize,
        key: Option<String>,
        normalized: Option<String>,
        class: Option<Class>,
        refused: Option<Reason>,
    }

    fn corpus() -> Corpus {
        serde_json::from_str(CORPUS).expect("the corpus is valid JSON")
    }

    /// The claim the README makes, checked against the RFC's own
    /// examples rather than against this code's output.
    #[test]
    fn every_pinned_normalization_follows_rfc_5952() {
        let corpus = corpus();
        assert!(!corpus.normalization.is_empty(), "the corpus pins nothing");
        for case in corpus.normalization {
            let Some(Reading::Address { normalized, .. }) = read(&case.input, Context::default())
            else {
                panic!("{} was not read as an address", case.input);
            };
            assert_eq!(normalized, case.expected, "{}: {}", case.input, case.why);
        }
    }

    /// The rules most likely to be lost: the longest zero run wins, not
    /// the first; a single zero group is never compressed; a mapped
    /// address keeps its dotted tail.
    #[test]
    fn the_corpus_pins_the_rules_that_are_easy_to_get_wrong() {
        let pinned: Vec<String> = corpus()
            .normalization
            .into_iter()
            .map(|case| case.expected)
            .collect();
        for form in ["2001:db8::1:0:0:1", "1:0:0:2::3", "::ffff:192.0.2.128"] {
            assert!(pinned.contains(&form.to_string()), "the corpus lost {form}");
        }
    }

    #[test]
    fn every_pinned_classification_reproduces() {
        for case in corpus().classification {
            let Some(Reading::Address { kind, class, .. }) = read(&case.input, Context::default())
            else {
                panic!("{} was not read as an address", case.input);
            };
            assert_eq!(kind, case.kind, "{}", case.input);
            assert_eq!(class, case.class, "{}", case.input);
        }
    }

    /// Every class has an address that reaches it, so the vocabulary
    /// cannot grow a value nothing checks.
    #[test]
    fn the_corpus_covers_every_class_and_every_kind() {
        let corpus = corpus();
        for class in [
            Class::Loopback,
            Class::Private,
            Class::LinkLocal,
            Class::Cgnat,
            Class::Multicast,
            Class::Broadcast,
            Class::Reserved,
            Class::Documentation,
            Class::UniqueLocal,
            Class::Global,
        ] {
            assert!(
                corpus.classification.iter().any(|case| case.class == class),
                "no corpus case reaches {class:?}"
            );
        }
        for kind in [Kind::Ipv4, Kind::Ipv6, Kind::Cidr, Kind::Mac] {
            assert!(
                corpus.classification.iter().any(|case| case.kind == kind),
                "no corpus case reaches {kind:?}"
            );
        }
    }

    /// **Every case here expects a refusal.** If one of these ever
    /// comes back as an address, a guess was introduced.
    #[test]
    fn every_ambiguous_case_is_refused_by_name() {
        let corpus = corpus();
        assert!(!corpus.ambiguity.is_empty(), "the corpus pins nothing");
        for case in corpus.ambiguity {
            let context = Context::from_key(case.key.as_deref());
            let Some(Reading::Refused { refusal, .. }) = read(&case.input, context) else {
                panic!("{} was not refused", case.input);
            };
            assert_eq!(refusal.reason, case.reason, "{}", case.input);
        }
    }

    /// Every refusal reason has a case, or the vocabulary carries a
    /// reason nothing produces.
    #[test]
    fn the_corpus_covers_every_refusal_reason() {
        let corpus = corpus();
        for reason in [
            Reason::AmbiguousVersion,
            Reason::MalformedAddress,
            Reason::OctalHazard,
            Reason::IntegerForm,
            Reason::PrefixOutOfRange,
            Reason::MacAmbiguous,
        ] {
            assert!(
                corpus.ambiguity.iter().any(|case| case.reason == reason),
                "no corpus case produces {reason:?}"
            );
        }
    }

    /// A real file per format, findings, positions and key paths
    /// included.
    #[test]
    fn every_corpus_document_reproduces() {
        let corpus = corpus();
        assert!(!corpus.documents.is_empty(), "the corpus is empty");
        for case in corpus.documents {
            let found: Vec<Expected> = find(document(&case.file), &case.format)
                .into_iter()
                .map(|one| Expected {
                    text: one.text,
                    line: one.line,
                    column: one.column,
                    key: one.key,
                    normalized: one.normalized,
                    class: one.class,
                    refused: one.refused.map(|refusal| refusal.reason),
                })
                .collect();
            assert_eq!(found, case.expected, "{}", case.name);
        }
    }

    #[test]
    fn the_corpus_covers_every_key_reader() {
        let corpus = corpus();
        for format in [
            "json", "yaml", "toml", "ini", "env", "csv", "log", "unknown",
        ] {
            assert!(
                corpus.documents.iter().any(|case| case.format == format),
                "no corpus document is read as {format}"
            );
        }
    }

    #[test]
    #[should_panic(expected = "no document named")]
    fn a_document_the_corpus_does_not_carry_is_a_broken_test() {
        document("nothing.json");
    }
}
