//! Reading a document: what addresses are in it, where, and what they
//! are.
//!
//! Nothing here touches the filesystem or the network — that is the
//! whole point of the split, and it is a stronger claim for this crate
//! than for its siblings. A tool that reports what an address *is* must
//! never be the tool that finds out by asking: no DNS, no connect, no
//! WHOIS, not once, not behind a flag. Classification is arithmetic
//! over the bits and the registries in `policy.rs`, and it stays that
//! way because a lookup would make the answer depend on the network the
//! auditor happened to be sitting on.
//!
//! ```text
//! scanner.rs   bytes  → candidate runs        (no format knows about this)
//! <format>.rs  bytes  → key spans             (json, yaml, toml, ini, env, csv, log)
//! policy.rs    run    → address or refusal    (the decision layer)
//! locate.rs    joins the three                (position, key, context)
//! ```

pub(crate) mod corpus;
pub(crate) mod csv;
pub(crate) mod dotenv;
pub(crate) mod format;
pub(crate) mod ini;
pub(crate) mod json;
pub(crate) mod locate;
pub(crate) mod log;
pub(crate) mod policy;
pub(crate) mod position;
pub(crate) mod scanner;
pub(crate) mod toml;
pub(crate) mod yaml;

use serde::Serialize;

pub(crate) use format::{FALLBACK_FORMAT, SUPPORTED_FORMATS, resolve_format};
pub(crate) use locate::find;
pub(crate) use policy::{Block, Class, Kind, Refusal};

/// One finding: an address, or a refusal to call something an address.
///
/// **Every field is always present**, nulls included. A consumer writes
/// one reader, and "the key is absent" and "the key is null" never have
/// to mean different things.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Found {
    /// `null` where the refusal is about *which* kind it is.
    pub(crate) kind: Option<Kind>,
    /// The text as the document spells it, never rewritten.
    pub(crate) text: String,
    pub(crate) line: usize,
    pub(crate) column: usize,
    /// The path to the value holding this address, where the format has
    /// one. Best effort, and `null` rather than a guess.
    pub(crate) key: Option<String>,
    /// The canonical form. IPv6 follows RFC 5952, which is the reason
    /// this tool is worth running: `2001:0db8::0001` and `2001:db8::1`
    /// are one address, and a dedupe over raw text says they are two.
    pub(crate) normalized: Option<String>,
    pub(crate) class: Option<Class>,
    pub(crate) cidr: Option<Block>,
    pub(crate) refused: Option<Refusal>,
}

impl Found {
    pub(crate) const fn is_refusal(&self) -> bool {
        self.refused.is_some()
    }

    /// Whether this finding survives a kind and class filter. Empty
    /// means every value of that dimension.
    ///
    /// **A refusal survives every filter it cannot be judged by.** A
    /// caller who asked for `private` is asking a question this tool
    /// declined to answer for `010.1.1.1`; dropping it would hide the
    /// one finding they most need, and hide it quietly.
    ///
    /// It lives here rather than on either surface's options because
    /// both surfaces filter — the CLI through `ScanOptions` and the
    /// `extract_ips` tool on its own arguments — and two copies of this
    /// rule would be two chances to lose a refusal on one of them.
    pub(crate) fn survives(&self, kinds: &[Kind], classes: &[Class]) -> bool {
        let kind_ok = kinds.is_empty()
            || self.kind.is_some_and(|kind| kinds.contains(&kind))
            || self.is_refusal() && self.kind.is_none();
        let class_ok = classes.is_empty()
            || self.class.is_some_and(|class| classes.contains(&class))
            || self.is_refusal();
        kind_ok && class_ok
    }
}

/// A region of the document that a key names, and the key.
///
/// Leaf values only, so spans never overlap and a lookup is a binary
/// search rather than a walk. A key is a locator, not a claim: nothing
/// in the report depends on it being right, which is what lets the
/// line-oriented readers be as simple as they are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeySpan {
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) path: String,
}

/// Each line of a document with the byte offset it starts at.
///
/// `str::lines` drops the offsets and every key reader here needs them.
/// A `\r` is left on the line for the readers to trim, so that a
/// Windows-written config does not silently carry it into a key.
pub(crate) fn lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    let mut offset = 0;
    text.split_inclusive('\n').map(move |line| {
        let start = offset;
        offset += line.len();
        (start, line.trim_end_matches(['\n', '\r']))
    })
}

/// A key under a section or table header, or the bare key when there is
/// none.
///
/// Shared by the INI and TOML readers, which spell a header differently
/// and join it identically. Two copies of a four-line join is how one of
/// them ends up emitting a leading `.` for a top-level key.
pub(crate) fn dotted(prefix: &str, key: &str) -> String {
    if prefix.is_empty() {
        return key.to_string();
    }
    format!("{prefix}.{key}")
}

/// Why a document yielded no key paths, when the reason is a parse
/// failure.
///
/// Only JSON can answer this: it is the one format here read by a
/// parser rather than line by line, and a line reader has no shape it
/// can reject. A JSON document that does not parse still gets its full
/// byte scan — the addresses are reported, and the diagnostic says the
/// key paths are missing rather than that nothing was found.
pub(crate) fn parse_error(text: &str, format: &str) -> Option<String> {
    match format::canonical(format) {
        "json" => json::parse_error(text),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_carry_the_offset_they_start_at() {
        let text = "a\nbb\nccc";
        let found: Vec<(usize, &str)> = lines(text).collect();
        assert_eq!(found, [(0, "a"), (2, "bb"), (5, "ccc")]);
        for (offset, line) in found {
            assert_eq!(&text[offset..offset + line.len()], line);
        }
    }

    #[test]
    fn a_windows_line_ending_is_not_part_of_the_line() {
        assert_eq!(
            lines("a\r\nb\r\n").collect::<Vec<_>>(),
            [(0, "a"), (3, "b")]
        );
    }

    #[test]
    fn only_json_can_fail_to_parse() {
        assert!(parse_error("{not json", "json").is_some());
        for format in ["yaml", "toml", "ini", "env", "csv", "log", "unknown"] {
            assert!(parse_error("{not json", format).is_none(), "{format}");
        }
    }
}
