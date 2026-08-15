//! Which key reader a document gets.
//!
//! **An unresolved format is not an error**, and here that matters more
//! than in any sibling: the scan runs over the bytes whatever the
//! format is, so a name nobody recognises costs a key path and nothing
//! else. Pointing this at a directory of `.conf`, `.tf`, `.rules` and
//! `.log.1` files has to work, because that is what the directory
//! holding the addresses looks like.
//!
//! `log` is a format here for one reason: it is where addresses
//! actually live. It resolves to its own name rather than to the
//! fallback because the reader for it is real — logfmt pairs and
//! JSON-per-line both carry keys — and because the name is user-visible
//! as `format` in every answer.

/// Every name a caller might send, mapped to the reader it means.
///
/// Both a VS Code `languageId` and a file extension appear here,
/// because a caller resolves by the first and a walk by the second.
const ALIASES: [(&str, &str); 20] = [
    ("json", "json"),
    ("jsonc", "json"),
    ("yaml", "yaml"),
    ("yml", "yaml"),
    ("toml", "toml"),
    ("ini", "ini"),
    ("cfg", "ini"),
    ("conf", "ini"),
    ("properties", "ini"),
    ("env", "env"),
    ("dotenv", "env"),
    ("csv", "csv"),
    ("tsv", "tsv"),
    ("log", "log"),
    ("logs", "log"),
    ("ndjson", "log"),
    ("jsonl", "log"),
    ("txt", FALLBACK_FORMAT),
    ("text", FALLBACK_FORMAT),
    ("plaintext", FALLBACK_FORMAT),
];

/// The formats a caller can name, for the tool schema's enum and for
/// `--format`. Held equal to the alias table by a test, so a format can
/// never be offered and then not resolve.
pub(crate) const SUPPORTED_FORMATS: [&str; 8] =
    ["json", "yaml", "toml", "ini", "env", "csv", "tsv", "log"];

/// What the engine uses when it recognises nothing: the byte scan with
/// no key paths.
pub(crate) const FALLBACK_FORMAT: &str = "unknown";

/// A name as the alias table spells it. The leading `.` goes before the
/// lowercasing rather than after, so this is one allocation instead of
/// two — case does not move a full stop.
fn normalise(value: &str) -> String {
    value.trim().trim_start_matches('.').to_lowercase()
}

/// The reader key for an already-canonical format name, or the
/// fallback. Used on the hot path, where the caller has resolved once.
pub(crate) fn canonical(format: &str) -> &'static str {
    ALIASES
        .iter()
        .find(|(alias, _)| *alias == format)
        .map_or(FALLBACK_FORMAT, |(_, key)| *key)
}

/// Resolve a reader key from an explicit format, else from a filename,
/// else the fallback.
pub(crate) fn resolve_format(format: Option<&str>, filename: Option<&str>) -> &'static str {
    if let Some(name) = format {
        let direct = canonical(&normalise(name));
        if direct != FALLBACK_FORMAT {
            return direct;
        }
    }

    let Some(filename) = filename else {
        return FALLBACK_FORMAT;
    };

    // A dotfile like `.env` has no extension to split on; its whole
    // name is the type.
    let whole = canonical(&normalise(filename));
    if whole != FALLBACK_FORMAT {
        return whole;
    }

    // `access.log.1` and `syslog.log.2026-08-12` are the same file as
    // `access.log`, and a rotated log is most of what a log directory
    // holds. Every suffix gets a try, right to left. The stem is skipped
    // rather than reversed into: `log.txt` is text, not a log.
    filename
        .split('.')
        .skip(1)
        .collect::<Vec<&str>>()
        .into_iter()
        .rev()
        .map(|part| canonical(&normalise(part)))
        .find(|key| *key != FALLBACK_FORMAT)
        .unwrap_or(FALLBACK_FORMAT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_offered_format_resolves_to_itself() {
        for format in SUPPORTED_FORMATS {
            assert_eq!(resolve_format(Some(format), None), format, "{format}");
        }
    }

    #[test]
    fn the_offered_list_matches_the_alias_table() {
        for format in SUPPORTED_FORMATS {
            assert_ne!(format, FALLBACK_FORMAT);
            assert!(
                ALIASES.iter().any(|(_, key)| *key == format),
                "{format} is offered but no alias produces it"
            );
        }
        for (_, key) in ALIASES {
            assert!(
                SUPPORTED_FORMATS.contains(&key) || key == FALLBACK_FORMAT,
                "{key} is produced but not offered"
            );
        }
    }

    #[test]
    fn aliases_are_honoured() {
        for (alias, expected) in [
            ("jsonc", "json"),
            ("yml", "yaml"),
            ("tsv", "tsv"),
            ("cfg", "ini"),
            ("conf", "ini"),
            ("dotenv", "env"),
            ("jsonl", "log"),
        ] {
            assert_eq!(resolve_format(Some(alias), None), expected, "{alias}");
        }
    }

    #[test]
    fn a_name_is_normalised_before_it_is_matched() {
        assert_eq!(resolve_format(Some("  JSON "), None), "json");
        assert_eq!(resolve_format(Some(".toml"), None), "toml");
    }

    #[test]
    fn a_filename_supplies_the_format_when_none_is_named() {
        assert_eq!(resolve_format(None, Some("config.toml")), "toml");
        assert_eq!(resolve_format(None, Some("data.CSV")), "csv");
        assert_eq!(resolve_format(None, Some("access.log")), "log");
    }

    /// A dotfile is its own extension.
    #[test]
    fn a_dotfile_resolves_by_its_whole_name() {
        assert_eq!(resolve_format(None, Some(".env")), "env");
        assert_eq!(resolve_format(None, Some("env")), "env");
    }

    /// A log directory is mostly rotated files, and a rotated log is
    /// still a log.
    #[test]
    fn a_rotated_log_is_still_a_log() {
        for name in ["access.log.1", "syslog.log.2026-08-12", "app.log.gz.log"] {
            assert_eq!(resolve_format(None, Some(name)), "log", "{name}");
        }
    }

    /// Not a refusal, not an empty result: the byte scan, with no key
    /// paths. A `.tf` file's addresses are still addresses.
    #[test]
    fn anything_unrecognised_falls_back() {
        for name in ["terraform", "dockerfile", "", "wat"] {
            assert_eq!(resolve_format(Some(name), None), FALLBACK_FORMAT, "{name}");
        }
        assert_eq!(resolve_format(None, Some("main.tf")), FALLBACK_FORMAT);
        assert_eq!(resolve_format(None, Some("Makefile")), FALLBACK_FORMAT);
        assert_eq!(resolve_format(None, None), FALLBACK_FORMAT);
    }

    /// An explicit format that resolves to nothing still lets the
    /// filename answer, rather than the bad name poisoning the lookup.
    #[test]
    fn an_unresolved_format_defers_to_the_filename() {
        assert_eq!(resolve_format(Some("nonsense"), Some("a.toml")), "toml");
    }
}
