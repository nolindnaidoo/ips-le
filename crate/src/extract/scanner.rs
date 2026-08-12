//! Which runs of text are worth asking `policy.rs` about.
//!
//! **Every format goes through here, over the whole document.** That is
//! the one decision this crate is built around, and it is the opposite
//! of what the sibling extractors do. A network address is almost never
//! a value — it is *inside* one: `postgres://10.0.0.5:5432/app`,
//! `Host: [2001:db8::1]:8080`, and above all a log line, which has no
//! values at all. An extractor that walked a parse tree and looked at
//! leaves would miss every one of them, so the scan reads the bytes and
//! the format parse only supplies the key path (`locate.rs`).
//!
//! The cost is that keys, comments and prose are scanned too. That is
//! the right trade here: an address hardcoded in a comment is an
//! address a reviewer came for.
//!
//! The hard part is **not** finding addresses. It is not finding
//! everything else. A log file is mostly timestamps, durations, ports,
//! hashes and paths, all built from the same alphabet, and a scanner
//! that handed them all to the policy layer would turn a refusal
//! vocabulary into noise. Three rules do most of that work:
//!
//! - **A run must not be glued to a name.** `Ipv6Addr::from_str`
//!   contains the text `::f`, which is a valid IPv6 address, and
//!   `v1.2.3.4` contains one too.
//! - **A colon run splits unless it looks like IPv6.** `127.0.0.1:5432`
//!   becomes the address and the port; `2026:10:30:00` becomes four
//!   numbers and no finding.
//! - **A hyphen run splits unless it is a MAC.** `10.0.0.1-10.0.0.9` is
//!   two addresses; `2026-08-12` is three numbers.

use std::ops::Range;

use super::policy;

/// One run of text to ask about, and where it starts.
///
/// A borrowed slice of the document, never a copy: the offset and the
/// text are two views of the same bytes, so they cannot disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Candidate<'a> {
    pub(crate) offset: usize,
    pub(crate) text: &'a str,
}

/// The alphabet an address is spelled from: hex digits and the three
/// separators. `%` is not here — a zone identifier names an interface
/// on one machine, and including it would glue `eth0` to the run.
fn is_address_byte(byte: u8) -> bool {
    byte.is_ascii_hexdigit() || is_separator_byte(byte)
}

fn is_separator_byte(byte: u8) -> bool {
    matches!(byte, b'.' | b':' | b'-')
}

/// A byte that continues an identifier.
fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Every candidate in a document, in order.
pub(crate) fn candidates(text: &str) -> Vec<Candidate<'_>> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut start = 0;

    while start < bytes.len() {
        if !is_address_byte(bytes[start]) {
            start += 1;
            continue;
        }
        let mut end = start;
        while end < bytes.len() && is_address_byte(bytes[end]) {
            end += 1;
        }
        let run = start..end;
        start = end;
        if let Some(run) = bound(bytes, run) {
            // A CIDR prefix sits past the run, so emitting can consume
            // more of the document than the run held.
            start = emit(text, run, &mut out).max(start);
        }
    }
    out
}

/// Narrow a run to the part that is not part of a name, or drop it.
///
/// The asymmetry is deliberate and is what separates two runs that look
/// identical to a character class: `client_ip:10.0.0.1` is a key and an
/// address, and `Ipv6Addr::from_str` is one identifier. A single
/// separator between a name and a run is punctuation; a `::` is a
/// language's path operator.
fn bound(bytes: &[u8], run: Range<usize>) -> Option<Range<usize>> {
    // Anything glued to the name that *follows* it is part of that
    // name: `2026-08-12T10:30:00Z`, `10.0.0.1z`.
    if run.end < bytes.len() && is_identifier_byte(bytes[run.end]) {
        return None;
    }
    if run.start == 0 || !is_identifier_byte(bytes[run.start - 1]) {
        return Some(run);
    }

    let lead_end = (run.start..run.end)
        .find(|index| !is_separator_byte(bytes[*index]))
        .unwrap_or(run.end);
    // `x10.0.0.1` and `v1.2.3.4`: nothing separates the run from the
    // name, so the run belongs to it.
    if lead_end == run.start {
        return None;
    }
    if bytes[run.start..lead_end]
        .windows(2)
        .any(|pair| pair == b"::")
    {
        return None;
    }
    (lead_end < run.end).then_some(lead_end..run.end)
}

/// Trim, split and record one run. Returns the offset the document has
/// been consumed to.
fn emit<'a>(text: &'a str, run: Range<usize>, out: &mut Vec<Candidate<'a>>) -> usize {
    let end = run.end;
    let Some((offset, token)) = trim(text, run.start, &text[run]) else {
        return end;
    };

    // A prefix belongs to the whole run or to nothing. `1:2/24` is not
    // a block, so a run that splits loses its `/24`.
    if !splits(token) {
        if let Some(suffix) = cidr_suffix(text, offset + token.len()) {
            let stop = offset + token.len() + suffix;
            out.push(Candidate {
                offset,
                text: &text[offset..stop],
            });
            return stop;
        }
        out.push(Candidate {
            offset,
            text: token,
        });
        return end;
    }

    // A separator this run does not use for an address. Every part is
    // re-read from scratch, so `10.0.0.1-10.0.0.9` yields two addresses
    // and `2026-08-12` yields three numbers nobody asked about.
    let separator = if token.contains('-') { '-' } else { ':' };
    let mut cursor = offset;
    for part in token.split(separator) {
        if let Some((at, trimmed)) = trim(text, cursor, part) {
            out.push(Candidate {
                offset: at,
                text: trimmed,
            });
        }
        cursor += part.len() + separator.len_utf8();
    }
    end
}

/// Whether a run has to be broken up before it can be read.
///
/// A hyphen is never an address separator except in a MAC, and a colon
/// is only one in IPv6 or a MAC — so a run holding either without the
/// shape to justify it is two things stuck together.
fn splits(token: &str) -> bool {
    if policy::is_mac_shaped(token) {
        return false;
    }
    if token.contains('-') {
        return true;
    }
    token.contains(':') && !policy::looks_like_ipv6(token)
}

/// Drop separators a run collected from the text around it: a
/// sentence's full stop, a range's dash, a `host:` with no port.
///
/// A **leading** colon is kept — `::1` is an address and `:1` is not,
/// and that difference is the policy layer's to make, not this one's.
fn trim<'a>(text: &'a str, offset: usize, token: &'a str) -> Option<(usize, &'a str)> {
    let trimmed = token.trim_end_matches(['.', '-']);
    let trimmed = if trimmed.ends_with("::") {
        trimmed
    } else {
        trimmed.trim_end_matches(':')
    };
    let lead = trimmed.len() - trimmed.trim_start_matches(['.', '-']).len();
    let trimmed = &trimmed[lead..];
    if trimmed.is_empty() {
        return None;
    }
    let offset = offset + lead;
    debug_assert_eq!(&text[offset..offset + trimmed.len()], trimmed);
    Some((offset, trimmed))
}

/// A `/` followed by one to three digits and then something that is not
/// part of a name. Returns the length to add to the run.
///
/// `/` is kept out of the run alphabet on purpose: a URL path would
/// otherwise glue itself to every address in a connection string.
fn cidr_suffix(text: &str, at: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    if bytes.get(at) != Some(&b'/') {
        return None;
    }
    let mut end = at + 1;
    while end < bytes.len() && bytes[end].is_ascii_digit() && end - at <= 3 {
        end += 1;
    }
    if end == at + 1 {
        return None;
    }
    if bytes.get(end).is_some_and(|byte| is_identifier_byte(*byte)) {
        return None;
    }
    Some(end - at)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens(text: &str) -> Vec<&str> {
        candidates(text)
            .into_iter()
            .map(|candidate| candidate.text)
            .collect()
    }

    fn offsets(text: &str) -> Vec<usize> {
        candidates(text)
            .into_iter()
            .map(|candidate| candidate.offset)
            .collect()
    }

    /// What the policy layer actually keeps. The scanner is deliberately
    /// generous — a lone `a` is a hex run — and the two together are the
    /// contract worth asserting.
    fn read(text: &str) -> Vec<&str> {
        candidates(text)
            .into_iter()
            .filter(|candidate| policy::read(candidate.text, policy::Context::default()).is_some())
            .map(|candidate| candidate.text)
            .collect()
    }

    #[test]
    fn an_address_is_found_with_its_offset() {
        assert_eq!(tokens("bind 10.0.0.1 now"), ["10.0.0.1"]);
        assert_eq!(offsets("bind 10.0.0.1 now"), [5]);
    }

    /// Every candidate is a slice of the document at the offset it
    /// claims. The whole position story rests on this.
    #[test]
    fn every_candidate_slices_the_document_it_came_from() {
        let text = "q=10.0.0.1:53, w=[2001:db8::1]:80, r=aa-bb-cc-dd-ee-ff, t=10.0.0.0/8\n";
        for candidate in candidates(text) {
            assert_eq!(
                &text[candidate.offset..candidate.offset + candidate.text.len()],
                candidate.text
            );
        }
    }

    #[test]
    fn a_port_is_split_off_its_host() {
        assert_eq!(tokens("127.0.0.1:5432"), ["127.0.0.1", "5432"]);
        assert_eq!(read("postgres://10.0.0.5:5432/app"), ["10.0.0.5"]);
    }

    #[test]
    fn a_bracketed_ipv6_address_survives_its_brackets_and_port() {
        assert_eq!(read("http://[2001:db8::1]:8080/x"), ["2001:db8::1"]);
    }

    /// The run that made the boundary rule necessary: `::f` is a real
    /// IPv6 address, and this is a Rust import.
    #[test]
    fn a_run_glued_to_a_name_is_not_a_candidate() {
        for text in [
            "use std::net::Ipv6Addr;",
            "let x = Vec::<u8>::new();",
            "x10.0.0.1",
            "10.0.0.1z",
            "released v1.2.3.4 today",
        ] {
            assert!(read(text).is_empty(), "{text} produced {:?}", read(text));
        }
    }

    /// And the case the rule must not break: a single separator between
    /// a name and a run is punctuation, not glue.
    #[test]
    fn one_separator_between_a_name_and_a_run_is_punctuation() {
        assert_eq!(read("client_ip:10.0.0.1"), ["10.0.0.1"]);
        assert_eq!(read("from=10.0.0.1"), ["10.0.0.1"]);
    }

    /// A log file is mostly this, and none of it is an address.
    #[test]
    fn timestamps_and_durations_are_not_addresses() {
        for text in [
            "2026-08-12T10:30:00Z",
            "[12/Aug/2026:10:30:00 +0000]",
            "took 1.25 ms",
            "v1.2.3",
            "elapsed 00:00:01.250",
        ] {
            assert!(read(text).is_empty(), "{text} produced {:?}", read(text));
        }
    }

    #[test]
    fn a_hyphen_range_is_two_candidates_and_a_mac_is_one() {
        assert_eq!(read("10.0.0.1-10.0.0.9"), ["10.0.0.1", "10.0.0.9"]);
        assert_eq!(read("aa-bb-cc-dd-ee-ff"), ["aa-bb-cc-dd-ee-ff"]);
        assert_eq!(read("aa:bb:cc:dd:ee:ff"), ["aa:bb:cc:dd:ee:ff"]);
    }

    /// The prefix is consumed, so its digits are not scanned twice.
    #[test]
    fn a_prefix_is_part_of_the_candidate_and_not_a_second_one() {
        assert_eq!(tokens("allow 10.0.0.0/8 here"), ["10.0.0.0/8"]);
        assert_eq!(tokens("allow 2001:db8::/32"), ["2001:db8::/32"]);
    }

    /// A URL path is not a prefix, which is why `/` is not in the run
    /// alphabet.
    #[test]
    fn a_url_path_is_not_a_prefix() {
        assert_eq!(read("http://10.0.0.1/api/v2"), ["10.0.0.1"]);
    }

    #[test]
    fn trailing_punctuation_is_not_part_of_an_address() {
        assert_eq!(read("reached 10.0.0.1."), ["10.0.0.1"]);
        assert_eq!(read("host 10.0.0.1:"), ["10.0.0.1"]);
        assert_eq!(read("prefix 2001:db8::"), ["2001:db8::"]);
    }

    #[test]
    fn an_uncompressed_ipv4_embedded_address_stays_whole() {
        assert_eq!(
            read("saw 0:0:0:0:0:ffff:192.0.2.1 once"),
            ["0:0:0:0:0:ffff:192.0.2.1"]
        );
        assert_eq!(
            read("saw 2001:db8:0:0:0:0:0:1 once"),
            ["2001:db8:0:0:0:0:0:1"]
        );
    }

    #[test]
    fn an_empty_document_yields_nothing() {
        assert!(candidates("").is_empty());
        assert!(read("no addresses in this prose").is_empty());
    }

    /// A multi-byte character before a run must not shift the offset.
    #[test]
    fn a_multibyte_document_keeps_its_offsets() {
        let text = "café 10.0.0.1";
        let found = candidates(text);
        let last = found.last().expect("a candidate");
        assert_eq!(last.text, "10.0.0.1");
        assert_eq!(&text[last.offset..], "10.0.0.1");
    }
}
