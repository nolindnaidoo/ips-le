//! What a candidate *is*, what it *means*, and when this tool refuses
//! to say — the whole decision layer, in one module with no I/O.
//!
//! `scanner.rs` decides what text is worth asking about. Everything
//! after that is here: shape, parse, normalization, classification, and
//! the six refusals. Two rules govern all of it.
//!
//! **Never resolve an ambiguity into an answer.** `010.1.1.1` is 8.1.1.1
//! to a resolver that reads a leading zero as octal and 10.1.1.1 to one
//! that reads it as decimal. Both readings exist in shipped software,
//! which is what makes it an SSRF bypass; a tool that picked one would
//! be the thing that hides the bug. So it is reported, flagged, and not
//! resolved.
//!
//! **Say the decoded form only next to the flag.** `2130706433` is
//! 127.0.0.1 through a 32-bit integer, and a reader needs to know that
//! to act. What they must not get is `2130706433` quietly turning into a
//! loopback address in a list of addresses, because then the flag is
//! gone and only the claim is left.

use std::net::{Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

/// What kind of network address a finding is.
///
/// A refusal may have none: `10.0.1` could be a truncated IPv4 or a
/// version string, and naming it `ipv4` would be the guess the refusal
/// exists to avoid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Kind {
    Ipv4,
    Ipv6,
    Cidr,
    Mac,
}

impl Kind {
    /// The names `--kind` accepts. Held equal to the enum by a test.
    pub(crate) const ALL: [&'static str; 4] = ["ipv4", "ipv6", "cidr", "mac"];

    pub(crate) fn parse(name: &str) -> Option<Self> {
        match name {
            "ipv4" => Some(Self::Ipv4),
            "ipv6" => Some(Self::Ipv6),
            "cidr" => Some(Self::Cidr),
            "mac" => Some(Self::Mac),
            _ => None,
        }
    }
}

/// What an address is *for*, which is the question a reviewer is
/// actually asking. Ten values, closed: a class this cannot name is a
/// class it does not claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Class {
    Loopback,
    Private,
    LinkLocal,
    Cgnat,
    Multicast,
    Broadcast,
    Reserved,
    Documentation,
    UniqueLocal,
    Global,
}

impl Class {
    /// The names `--class` accepts. Held equal to the enum by a test.
    pub(crate) const ALL: [&'static str; 10] = [
        "loopback",
        "private",
        "link-local",
        "cgnat",
        "multicast",
        "broadcast",
        "reserved",
        "documentation",
        "unique-local",
        "global",
    ];

    pub(crate) fn parse(name: &str) -> Option<Self> {
        match name {
            "loopback" => Some(Self::Loopback),
            "private" => Some(Self::Private),
            "link-local" => Some(Self::LinkLocal),
            "cgnat" => Some(Self::Cgnat),
            "multicast" => Some(Self::Multicast),
            "broadcast" => Some(Self::Broadcast),
            "reserved" => Some(Self::Reserved),
            "documentation" => Some(Self::Documentation),
            "unique-local" => Some(Self::UniqueLocal),
            "global" => Some(Self::Global),
            _ => None,
        }
    }

    /// The name the human line prints, which is the name the JSON
    /// carries.
    ///
    /// Exhaustive on purpose: a new class fails to compile here rather
    /// than reaching stderr as an empty word. A test holds every answer
    /// equal to what serde renders, so the two spellings cannot drift.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::Private => "private",
            Self::LinkLocal => "link-local",
            Self::Cgnat => "cgnat",
            Self::Multicast => "multicast",
            Self::Broadcast => "broadcast",
            Self::Reserved => "reserved",
            Self::Documentation => "documentation",
            Self::UniqueLocal => "unique-local",
            Self::Global => "global",
        }
    }
}

/// Why this tool declined to say what a candidate is.
///
/// Every one of these is a case where more than one answer is
/// defensible from the text alone. Naming the reason is what makes a
/// refusal actionable: a reader who knows *which* ambiguity they have
/// knows what to go and check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Reason {
    /// A dotted decimal that could be an address or a version.
    AmbiguousVersion,
    /// The right shape, and it did not parse.
    MalformedAddress,
    /// A leading zero: octal to some resolvers, decimal to others.
    OctalHazard,
    /// A bare integer in an address field — a dotted quad written as a
    /// 32-bit number.
    IntegerForm,
    /// A CIDR prefix outside 0–32 (v4) or 0–128 (v6).
    PrefixOutOfRange,
    /// Twelve hex digits with no separator: a MAC or a truncated hash.
    MacAmbiguous,
}

/// A refusal, and the sentence a reader acts on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Refusal {
    pub(crate) reason: Reason,
    pub(crate) detail: String,
}

/// What a CIDR block covers.
///
/// `hosts` is a decimal **string**. `::/0` holds 2^128 addresses, which
/// is neither a JSON number a reader can trust nor a `u128` — and a
/// count silently clamped to `u128::MAX` would be off by exactly the
/// one address that makes it wrong.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Block {
    pub(crate) prefix: u8,
    pub(crate) network: String,
    /// IPv4 only. IPv6 has no broadcast address — `null` here is that
    /// fact, not a value this failed to compute.
    pub(crate) broadcast: Option<String>,
    pub(crate) last: String,
    pub(crate) hosts: String,
}

/// What a candidate turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Reading {
    Address {
        kind: Kind,
        normalized: String,
        class: Class,
        block: Option<Block>,
    },
    Refused {
        kind: Option<Kind>,
        refusal: Refusal,
    },
}

/// The evidence outside the token itself, gathered by `locate.rs`.
///
/// The refusals are conditional on this. A dotted triple is a version
/// under `"version": "10.0.1"` and an ambiguity in a log line, and the
/// only difference between those two is what surrounds them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Context {
    /// The key, or the character before the token, says "version".
    pub(crate) version: bool,
    /// The key says "address": `ip`, `addr`, `address`, `host`,
    /// `gateway`.
    pub(crate) address: bool,
}

impl Context {
    /// Whether a key names an address field. Matched on the last
    /// segment, by suffix, so `remote_ip` and `bind-address` count and
    /// `description` does not.
    pub(crate) fn from_key(key: Option<&str>) -> Self {
        let Some(key) = key else {
            return Self::default();
        };
        let last = key.rsplit(['.', '/']).next().unwrap_or(key);
        let flat: String = last
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .map(|character| character.to_ascii_lowercase())
            .collect();
        Self {
            version: flat.contains("version") || flat == "ver" || flat == "rev",
            address: ["ip", "addr", "address", "host", "gateway", "cidr", "subnet"]
                .iter()
                .any(|suffix| flat.ends_with(suffix)),
        }
    }
}

/// Read one candidate token.
///
/// `None` means "this is not a network address and not an ambiguity
/// either" — a port, a timestamp, a plain number. Silence is the right
/// answer far more often than a finding is, and a tool that reported
/// every colon-separated run would be unusable on the log files this
/// exists to read.
pub(crate) fn read(token: &str, context: Context) -> Option<Reading> {
    if let Some((base, prefix)) = token.split_once('/') {
        return read_cidr(base, prefix);
    }
    if let Some(octets) = mac_octets(token) {
        return Some(read_mac(octets));
    }
    if token.contains(':') {
        // Gated on the shape rather than on the parse. `10:30:00` and
        // `host:8080` have colons and are not malformed addresses, and
        // calling them that would put a refusal on every line of every
        // log file.
        return looks_like_ipv6(token).then(|| read_ipv6(token));
    }
    if token.contains('.') {
        return read_dotted(token, context);
    }
    read_bare(token, context)
}

/// Whether a colon run is IPv6-shaped enough to be read as one.
///
/// Deliberately strict. Seven colons is a full address; `::` is a
/// compressed one; six colons with a dotted tail is the uncompressed
/// IPv4-embedded form. Everything else — a `host:port`, a clock time, a
/// log timestamp — is not an address and not a refusal either.
///
/// `scanner.rs` asks the same question, to decide whether to hand a run
/// over whole or split it on its colons. One implementation, so the two
/// answers cannot drift apart and drop every IPv6 address silently.
pub(crate) fn looks_like_ipv6(token: &str) -> bool {
    if token.contains("::") {
        return true;
    }
    let colons = token.bytes().filter(|byte| *byte == b':').count();
    if colons == 7 {
        return true;
    }
    let dotted_tail = token
        .rsplit(':')
        .next()
        .is_some_and(|tail| tail.split('.').count() == 4);
    colons == 6 && dotted_tail
}

// -- IPv4 ------------------------------------------------------------

/// A dotted run of decimal groups: an address, a version, or a hazard.
fn read_dotted(token: &str, context: Context) -> Option<Reading> {
    let groups: Vec<&str> = token.split('.').collect();
    if !groups
        .iter()
        .all(|group| !group.is_empty() && group.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return None;
    }

    // Four groups is the IPv4 shape, and a leading zero in one of them
    // is the SSRF bypass — checked before parsing, because `Ipv4Addr`
    // rejects it and a rejection would be reported as `malformed`,
    // which names the wrong problem.
    if groups.len() == 4 {
        if let Some(hazard) = octal_hazard(token, &groups) {
            return Some(hazard);
        }
        if context.version {
            return None;
        }
        return Some(read_ipv4(token));
    }

    // Three groups is not an address. It is a version, or a truncated
    // address, and nothing in the text says which.
    if groups.len() == 3 {
        if context.version {
            return None;
        }
        return Some(Reading::Refused {
            kind: None,
            refusal: Refusal {
                reason: Reason::AmbiguousVersion,
                detail: format!(
                    "{token} has three groups: a version string, or an IPv4 address missing an \
                     octet. Nothing here says which."
                ),
            },
        });
    }

    // Two groups, or five and up. Neither shape is an address at all,
    // and reporting them would put every decimal number and every OID
    // in the report.
    None
}

fn octal_hazard(token: &str, groups: &[&str]) -> Option<Reading> {
    if !groups
        .iter()
        .any(|group| group.len() > 1 && group.starts_with('0'))
    {
        return None;
    }
    Some(Reading::Refused {
        kind: Some(Kind::Ipv4),
        refusal: Refusal {
            reason: Reason::OctalHazard,
            detail: format!(
                "{token} has a leading zero. Some resolvers read a leading-zero octet as octal \
                 and some as decimal, so this text has two addresses and no way to choose."
            ),
        },
    })
}

fn read_ipv4(token: &str) -> Reading {
    let Ok(address) = token.parse::<Ipv4Addr>() else {
        return Reading::Refused {
            kind: Some(Kind::Ipv4),
            refusal: Refusal {
                reason: Reason::MalformedAddress,
                detail: format!("{token} has four groups and is not an IPv4 address."),
            },
        };
    };
    Reading::Address {
        kind: Kind::Ipv4,
        normalized: address.to_string(),
        class: class_of_v4(address),
        block: None,
    }
}

// -- IPv6 ------------------------------------------------------------

fn read_ipv6(token: &str) -> Reading {
    // A zone identifier names an interface on *this* machine, not a
    // part of the address, and no two machines agree on `%eth0`. It is
    // dropped before parsing; the raw text keeps it.
    let bare = token.split('%').next().unwrap_or(token);
    let Ok(address) = bare.parse::<Ipv6Addr>() else {
        return Reading::Refused {
            kind: Some(Kind::Ipv6),
            refusal: Refusal {
                reason: Reason::MalformedAddress,
                detail: format!("{token} has the shape of an IPv6 address and is not one."),
            },
        };
    };
    Reading::Address {
        kind: Kind::Ipv6,
        normalized: address.to_string(),
        class: class_of_v6(address),
        block: None,
    }
}

// -- CIDR ------------------------------------------------------------

fn read_cidr(base: &str, prefix: &str) -> Option<Reading> {
    // A `/` after something with no address shape at all is a path or a
    // fraction. Deciding that here, before the prefix is even read,
    // keeps `src/v1.2` and `1/2` out of the report entirely.
    let shaped = if base.contains(':') {
        looks_like_ipv6(base)
    } else {
        base.split('.').count() == 4
    };
    if !shaped {
        return None;
    }

    // A run of digits **is** a prefix; whether it fits the family is the
    // range question below. Only text that is not a number at all is
    // malformed — deciding that by whether the digits happen to fit a
    // `u16` would name the same mistake two different ways.
    //
    // `scanner.rs` only ever attaches one to three digits after a `/`,
    // so no document reaches the malformed branch today. It stays
    // because `read` is the entry point for a token from anywhere, and
    // the alternative is a block whose prefix nobody parsed.
    if prefix.is_empty() || !prefix.bytes().all(|byte| byte.is_ascii_digit()) {
        return Some(refuse_cidr(
            Reason::MalformedAddress,
            format!("{base}/{prefix} does not carry a prefix length."),
        ));
    }
    // Saturating rather than failing: digits too long for a `u16` are
    // certainly outside both families, and the refusal prints the text
    // the document wrote rather than this number.
    let width = prefix.parse::<u16>().unwrap_or(u16::MAX);

    if base.contains(':') {
        return Some(cidr_v6(base, width));
    }
    Some(cidr_v4(base, width))
}

fn cidr_v4(base: &str, prefix: u16) -> Reading {
    let groups: Vec<&str> = base.split('.').collect();
    if let Some(hazard) = octal_hazard(base, &groups) {
        return hazard;
    }
    let Ok(address) = base.parse::<Ipv4Addr>() else {
        return refuse_cidr(
            Reason::MalformedAddress,
            format!("{base}/{prefix} does not carry an IPv4 address."),
        );
    };
    // Narrowing **is** the range check: 0 to 32 fits a `u8` and nothing
    // outside it does, so there is no fallback here and the arithmetic
    // below can never run on a prefix nobody checked.
    let width = u8::try_from(prefix).ok().filter(|width| *width <= 32);
    let Some(prefix) = width else {
        return refuse_cidr(
            Reason::PrefixOutOfRange,
            format!("an IPv4 prefix is 0 to 32; {base}/{prefix} names {prefix}."),
        );
    };

    let bits = u32::from(address);
    // `/0` asks to shift by the full width, which Rust refuses rather
    // than wraps. The mask it is asking for is zero, and saying so here
    // is what keeps `0.0.0.0/0` from covering one address instead of
    // all of them.
    let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
    let network = Ipv4Addr::from(bits & mask);
    let last = Ipv4Addr::from((bits & mask) | !mask);
    Reading::Address {
        kind: Kind::Cidr,
        normalized: format!("{address}/{prefix}"),
        class: class_of_v4(network),
        block: Some(Block {
            prefix,
            network: network.to_string(),
            broadcast: Some(last.to_string()),
            last: last.to_string(),
            hosts: (1u128 << (32 - u32::from(prefix))).to_string(),
        }),
    }
}

fn cidr_v6(base: &str, prefix: u16) -> Reading {
    let without_zone = base.split('%').next().unwrap_or(base);
    let Ok(address) = without_zone.parse::<Ipv6Addr>() else {
        return refuse_cidr(
            Reason::MalformedAddress,
            format!("{base}/{prefix} does not carry an IPv6 address."),
        );
    };
    // As in `cidr_v4`: the narrowing is the range check, so nothing
    // downstream runs on an unchecked prefix.
    let width = u8::try_from(prefix).ok().filter(|width| *width <= 128);
    let Some(prefix) = width else {
        return refuse_cidr(
            Reason::PrefixOutOfRange,
            format!("an IPv6 prefix is 0 to 128; {base}/{prefix} names {prefix}."),
        );
    };

    let bits = u128::from(address);
    // `::/0` shifts by the full width; the mask it asks for is zero.
    let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
    let network = Ipv6Addr::from(bits & mask);
    let last = Ipv6Addr::from((bits & mask) | !mask);
    Reading::Address {
        kind: Kind::Cidr,
        normalized: format!("{address}/{prefix}"),
        class: class_of_v6(network),
        block: Some(Block {
            prefix,
            network: network.to_string(),
            broadcast: None,
            last: last.to_string(),
            hosts: v6_hosts(prefix),
        }),
    }
}

/// 2^(128 − prefix), as decimal text.
///
/// `::/0` is the one that does not fit: 2^128 is one more than
/// `u128::MAX`, so it is spelled out rather than computed. Pinned by a
/// test, because a wrong constant here is the kind of thing nobody
/// checks by eye.
fn v6_hosts(prefix: u8) -> String {
    if prefix == 0 {
        return "340282366920938463463374607431768211456".to_string();
    }
    (1u128 << (128 - u32::from(prefix))).to_string()
}

fn refuse_cidr(reason: Reason, detail: String) -> Reading {
    Reading::Refused {
        kind: Some(Kind::Cidr),
        refusal: Refusal { reason, detail },
    }
}

// -- MAC -------------------------------------------------------------

/// The six octets of a MAC address, or `None` for anything that is not
/// one.
///
/// Six two-digit hex groups joined by one separator, `:` or `-`, used
/// consistently. `aa:bb-cc:dd-ee:ff` is not a MAC address and mixing
/// them is how a hand-written line ends up being read as one.
///
/// **Shape and value in one answer**, so the test and the read cannot
/// disagree. `scanner.rs` asks this same question — it has to hold a run
/// together for exactly the tokens this will read as a MAC — and a test
/// there holds the two answers equal.
pub(crate) fn mac_octets(token: &str) -> Option<[u8; 6]> {
    [':', '-']
        .into_iter()
        .find_map(|separator| octets_under(token, separator))
}

fn octets_under(token: &str, separator: char) -> Option<[u8; 6]> {
    let groups: Vec<&str> = token.split(separator).collect();
    // Six, and no seventh: `aa:bb:cc:dd:ee:ff:zz` is not a MAC address
    // with a suffix, it is not a MAC address.
    if groups.len() != 6 {
        return None;
    }
    let octets: Vec<u8> = groups.iter().copied().filter_map(group_octet).collect();
    <[u8; 6]>::try_from(octets.as_slice()).ok()
}

/// Exactly two hex digits, and the byte they spell. Two hex digits never
/// exceed `0xff`, so the radix conversion cannot overflow.
fn group_octet(group: &str) -> Option<u8> {
    if group.len() != 2 || !group.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    u8::from_str_radix(group, 16).ok()
}

fn read_mac(octets: [u8; 6]) -> Reading {
    // Three statements a MAC's own bits support, and no more. The
    // universal/local bit is deliberately not reported in 0.1.0 —
    // SPEC.md says so — because none of the ten classes means it.
    let class = match octets {
        [0xff, 0xff, 0xff, 0xff, 0xff, 0xff] => Class::Broadcast,
        [first, ..] if first & 1 == 1 => Class::Multicast,
        _ => Class::Global,
    };
    Reading::Address {
        kind: Kind::Mac,
        normalized: octets
            .iter()
            .map(|octet| format!("{octet:02x}"))
            .collect::<Vec<String>>()
            .join(":"),
        class,
        block: None,
    }
}

// -- Bare tokens -----------------------------------------------------

/// A token with no separators in it: a number, or twelve hex digits.
///
/// Both refusals here are gated hard, because the alternative is a
/// finding for every integer and every short hash in the tree — a
/// report nobody reads is not a safer report.
fn read_bare(token: &str, context: Context) -> Option<Reading> {
    if token.bytes().all(|byte| byte.is_ascii_digit()) {
        // Only in a field that names an address. `timeout = 2130706433`
        // is a number; `bind_ip = 2130706433` is a loopback bypass, and
        // nothing but the key tells them apart.
        if !context.address {
            return None;
        }
        let value = token.parse::<u32>().ok()?;
        return Some(Reading::Refused {
            kind: Some(Kind::Ipv4),
            refusal: Refusal {
                reason: Reason::IntegerForm,
                detail: format!(
                    "{token} in an address field is {} read as a 32-bit integer. Some resolvers \
                     accept that form; this tool will not decide that they did.",
                    Ipv4Addr::from(value)
                ),
            },
        });
    }

    // Twelve hex digits with at least one letter in them. All-digits is
    // a number, and any other length is not a MAC address at all — a
    // 40-character commit hash never reaches this.
    let mac_like = token.len() == 12
        && token.bytes().all(|byte| byte.is_ascii_hexdigit())
        && token.bytes().any(|byte| byte.is_ascii_alphabetic());
    if !mac_like {
        return None;
    }
    Some(Reading::Refused {
        kind: None,
        refusal: Refusal {
            reason: Reason::MacAmbiguous,
            detail: format!(
                "{token} is twelve hex digits with no separators: a MAC address written bare, or \
                 the front of a hash. Nothing here says which."
            ),
        },
    })
}

// -- Classification --------------------------------------------------

/// What an IPv4 address is for.
///
/// Order is load-bearing: the broadcast address is inside 240/4, and
/// the three documentation blocks are inside ranges that would
/// otherwise read as global.
fn class_of_v4(address: Ipv4Addr) -> Class {
    match address.octets() {
        [127, ..] => Class::Loopback,
        [10, ..] | [192, 168, ..] => Class::Private,
        [172, second, ..] if (16..=31).contains(&second) => Class::Private,
        [169, 254, ..] => Class::LinkLocal,
        [100, second, ..] if (64..=127).contains(&second) => Class::Cgnat,
        [255, 255, 255, 255] => Class::Broadcast,
        // RFC 5737 (v4) — the addresses documentation is allowed to use,
        // which is exactly why finding one in a config is worth seeing.
        [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _] => Class::Documentation,
        [224..=239, ..] => Class::Multicast,
        // "this network" (0/8) and future use (240/4), then IETF
        // protocol assignments (192.0.0/24) and benchmarking (198.18/15).
        [0 | 240..=255, ..] | [192, 0, 0, _] | [198, 18 | 19, ..] => Class::Reserved,
        _ => Class::Global,
    }
}

/// What an IPv6 address is for.
fn class_of_v6(address: Ipv6Addr) -> Class {
    // `::ffff:127.0.0.1` is loopback, and calling it `global` is the
    // exact miss an allow-list review is trying to find.
    if let Some(mapped) = address.to_ipv4_mapped() {
        return class_of_v4(mapped);
    }
    if address == Ipv6Addr::LOCALHOST {
        return Class::Loopback;
    }
    if address == Ipv6Addr::UNSPECIFIED {
        return Class::Reserved;
    }

    let segments = address.segments();
    if segments[0] & 0xff00 == 0xff00 {
        return Class::Multicast;
    }
    if segments[0] & 0xffc0 == 0xfe80 {
        return Class::LinkLocal;
    }
    if segments[0] & 0xfe00 == 0xfc00 {
        return Class::UniqueLocal;
    }
    // RFC 3849.
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return Class::Documentation;
    }
    // 2001::/23, IETF protocol assignments — Teredo, ORCHID, benchmark.
    if segments[0] == 0x2001 && segments[1] < 0x0200 {
        return Class::Reserved;
    }
    // 100::/64, the discard-only prefix.
    if segments[0] == 0x0100 && segments[1..4] == [0, 0, 0] {
        return Class::Reserved;
    }
    Class::Global
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(token: &str) -> (Kind, String, Class) {
        match read(token, Context::default()).expect("a reading") {
            Reading::Address {
                kind,
                normalized,
                class,
                ..
            } => (kind, normalized, class),
            Reading::Refused { refusal, .. } => {
                panic!("{token} was refused: {:?}", refusal.reason)
            }
        }
    }

    fn refusal(token: &str, context: Context) -> Reason {
        match read(token, context).expect("a reading") {
            Reading::Refused { refusal, .. } => refusal.reason,
            Reading::Address { normalized, .. } => {
                panic!("{token} was read as {normalized}")
            }
        }
    }

    fn block(token: &str) -> Block {
        match read(token, Context::default()).expect("a reading") {
            Reading::Address { block, .. } => block.expect("a block"),
            Reading::Refused { refusal, .. } => {
                panic!("{token} was refused: {:?}", refusal.reason)
            }
        }
    }

    #[test]
    fn an_ipv4_address_is_read_and_classified() {
        assert_eq!(
            address("192.168.1.1"),
            (Kind::Ipv4, "192.168.1.1".to_string(), Class::Private)
        );
    }

    /// The reason this crate exists. Four spellings of one address, one
    /// normalized form — a string dedupe over the raw text reports four
    /// distinct addresses and is wrong four times.
    #[test]
    fn four_spellings_of_one_ipv6_address_normalize_together() {
        for token in [
            "2001:0db8:0000:0000:0000:0000:0000:0001",
            "2001:db8:0:0:0:0:0:1",
            "2001:0db8::0001",
            "2001:DB8::1",
        ] {
            assert_eq!(address(token).1, "2001:db8::1", "{token}");
        }
    }

    #[test]
    fn every_ipv4_class_has_an_address_that_reaches_it() {
        for (token, expected) in [
            ("127.0.0.1", Class::Loopback),
            ("10.1.2.3", Class::Private),
            ("172.16.0.1", Class::Private),
            ("172.32.0.1", Class::Global),
            ("192.168.0.1", Class::Private),
            ("169.254.169.254", Class::LinkLocal),
            ("100.64.0.1", Class::Cgnat),
            ("100.128.0.1", Class::Global),
            ("224.0.0.1", Class::Multicast),
            ("255.255.255.255", Class::Broadcast),
            ("192.0.2.5", Class::Documentation),
            ("198.51.100.5", Class::Documentation),
            ("203.0.113.5", Class::Documentation),
            ("0.0.0.0", Class::Reserved),
            ("192.0.0.8", Class::Reserved),
            ("198.18.0.1", Class::Reserved),
            ("240.0.0.1", Class::Reserved),
            ("8.8.8.8", Class::Global),
        ] {
            assert_eq!(address(token).2, expected, "{token}");
        }
    }

    #[test]
    fn every_ipv6_class_has_an_address_that_reaches_it() {
        for (token, expected) in [
            ("::1", Class::Loopback),
            ("::", Class::Reserved),
            ("fe80::1", Class::LinkLocal),
            ("fd00::1", Class::UniqueLocal),
            ("ff02::1", Class::Multicast),
            ("2001:db8::1", Class::Documentation),
            ("2001:0:1::1", Class::Reserved),
            ("100::1", Class::Reserved),
            ("2606:4700:4700::1111", Class::Global),
        ] {
            assert_eq!(address(token).2, expected, "{token}");
        }
    }

    /// The SSRF case an allow-list review is looking for: a mapped
    /// address is the address it maps, not a global one.
    #[test]
    fn an_ipv4_mapped_address_takes_the_ipv4_class() {
        assert_eq!(address("::ffff:127.0.0.1").2, Class::Loopback);
        assert_eq!(address("::ffff:169.254.169.254").2, Class::LinkLocal);
    }

    #[test]
    fn a_mac_address_is_lowercased_and_colon_separated() {
        assert_eq!(
            address("AA-BB-CC-DD-EE-FF"),
            (Kind::Mac, "aa:bb:cc:dd:ee:ff".to_string(), Class::Global)
        );
        assert_eq!(address("ff:ff:ff:ff:ff:ff").2, Class::Broadcast);
        assert_eq!(address("01:00:5e:00:00:01").2, Class::Multicast);
    }

    /// Mixing separators is how a line of hand-written text gets read
    /// as hardware, so the shape requires one separator throughout.
    #[test]
    fn a_mac_with_mixed_separators_is_not_a_mac() {
        assert!(read("aa:bb-cc:dd-ee:ff", Context::default()).is_none());
    }

    /// Six groups exactly. A seventh group whose contents are not hex
    /// must not be discarded and the front read as hardware.
    #[test]
    fn a_seventh_group_is_not_a_mac_with_a_suffix() {
        for token in [
            "aa:bb:cc:dd:ee:ff:zz",
            "aa:bb:cc:dd:ee:ff:00",
            "aa:bb:cc:dd:ee",
            "aa:bb:cc:dd:ee:fff",
            "aa:bb:cc:dd:ee:zz",
        ] {
            assert!(mac_octets(token).is_none(), "{token}");
        }
        assert_eq!(
            mac_octets("aa:bb:cc:dd:ee:ff"),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
    }

    // -- the refusals ------------------------------------------------

    #[test]
    fn a_leading_zero_is_an_octal_hazard_and_is_never_resolved() {
        for token in ["010.1.1.1", "0177.0.0.1", "192.168.001.1"] {
            assert_eq!(refusal(token, Context::default()), Reason::OctalHazard);
        }
        // The whole point: the octal reading never appears, and the
        // decimal one appears only as the text the document wrote.
        let Some(Reading::Refused { refusal, .. }) = read("010.1.1.1", Context::default()) else {
            panic!("a refusal");
        };
        assert!(!refusal.detail.contains("8.1.1.1"), "{}", refusal.detail);
        assert!(
            !refusal.detail.replace("010.1.1.1", "").contains("10.1.1.1"),
            "{}",
            refusal.detail
        );
    }

    /// A single `0` octet is not a leading zero.
    #[test]
    fn an_ordinary_zero_octet_is_not_a_hazard() {
        assert_eq!(address("10.0.0.1").1, "10.0.0.1");
    }

    #[test]
    fn a_dotted_triple_is_ambiguous_unless_the_key_says_version() {
        assert_eq!(
            refusal("10.0.1", Context::default()),
            Reason::AmbiguousVersion
        );
        assert!(
            read(
                "10.0.1",
                Context {
                    version: true,
                    ..Context::default()
                }
            )
            .is_none()
        );
    }

    /// A four-group dotted decimal under a version key is a version.
    /// Reading it as an address is the guess in the other direction.
    #[test]
    fn a_version_key_suppresses_a_four_group_reading_too() {
        assert!(
            read(
                "1.2.3.4",
                Context {
                    version: true,
                    ..Context::default()
                }
            )
            .is_none()
        );
        assert_eq!(address("1.2.3.4").0, Kind::Ipv4);
    }

    #[test]
    fn a_four_group_run_that_is_not_an_address_is_malformed() {
        for token in ["256.1.1.1", "1.2.3.9999"] {
            assert_eq!(refusal(token, Context::default()), Reason::MalformedAddress);
        }
    }

    #[test]
    fn an_ipv6_shape_that_does_not_parse_is_malformed() {
        for token in ["12345::1", "1::2::3", "2001:db8:::1"] {
            assert_eq!(refusal(token, Context::default()), Reason::MalformedAddress);
        }
    }

    /// The decoded form appears **only** inside the refusal, so a reader
    /// can never get the address without the flag that says it was a
    /// guess.
    #[test]
    fn an_integer_in_an_address_field_is_flagged_and_decoded_together() {
        let context = Context {
            address: true,
            ..Context::default()
        };
        let Some(Reading::Refused { refusal, .. }) = read("2130706433", context) else {
            panic!("a refusal");
        };
        assert_eq!(refusal.reason, Reason::IntegerForm);
        assert!(refusal.detail.contains("127.0.0.1"), "{}", refusal.detail);
    }

    /// Outside an address field it is a number, and a report that
    /// flagged every integer would not be read at all.
    #[test]
    fn a_bare_integer_with_no_address_context_is_not_a_finding() {
        assert!(read("2130706433", Context::default()).is_none());
    }

    #[test]
    fn twelve_bare_hex_digits_are_ambiguous() {
        assert_eq!(
            refusal("deadbeefcafe", Context::default()),
            Reason::MacAmbiguous
        );
        // All digits is a number, and any other length is not a MAC.
        assert!(read("123456789012", Context::default()).is_none());
        assert!(read("deadbeefcafeff", Context::default()).is_none());
    }

    #[test]
    fn a_prefix_outside_its_family_is_refused() {
        assert_eq!(
            refusal("10.0.0.0/33", Context::default()),
            Reason::PrefixOutOfRange
        );
        assert_eq!(
            refusal("2001:db8::/129", Context::default()),
            Reason::PrefixOutOfRange
        );
    }

    /// A prefix too wide for a `u8` is out of range for the same reason
    /// `/33` is, and must not come back as a different refusal because
    /// of how it is stored. The scanner reads at most three digits, so
    /// `/999` is the widest prefix that can reach here from a document.
    #[test]
    fn a_prefix_too_wide_to_narrow_is_still_out_of_range() {
        for token in ["10.0.0.0/999", "2001:db8::/999"] {
            assert_eq!(
                refusal(token, Context::default()),
                Reason::PrefixOutOfRange,
                "{token}"
            );
        }
    }

    /// A block whose base is the right shape and not an address is
    /// malformed, on both families — the prefix is beside the point.
    #[test]
    fn a_block_over_a_base_that_is_not_an_address_is_malformed() {
        for token in [
            "256.1.1.1/24",
            "1.2.3.9999/8",
            "2001:db8:::1/64",
            "12345::/16",
        ] {
            assert_eq!(
                refusal(token, Context::default()),
                Reason::MalformedAddress,
                "{token}"
            );
        }
    }

    /// A prefix that is not a number at all. No document reaches this —
    /// the scanner attaches only digits to a `/` — but `read` takes a
    /// token from anywhere, and the answer has to be a named refusal
    /// rather than a block whose prefix nobody parsed.
    #[test]
    fn a_prefix_that_is_not_a_number_is_malformed() {
        for token in ["10.0.0.0/abc", "2001:db8::/x", "10.0.0.0/"] {
            assert_eq!(
                refusal(token, Context::default()),
                Reason::MalformedAddress,
                "{token}"
            );
        }
    }

    /// A run of digits **is** a prefix; whether it fits the family is
    /// the range question. Storing it decided the reason before that:
    /// `/999` fitted a `u16` and answered `prefix_out_of_range` while
    /// `/65536` did not and answered `malformed_address` — the same
    /// mistake, named two ways, for a reason with nothing to do with
    /// the document.
    #[test]
    fn a_prefix_of_digits_is_out_of_range_however_long_it_is() {
        for token in [
            "10.0.0.0/33",
            "10.0.0.0/999",
            "10.0.0.0/65536",
            "10.0.0.0/99999999999999999999",
            "2001:db8::/129",
            "2001:db8::/65536",
            "2001:db8::/99999999999999999999",
        ] {
            assert_eq!(
                refusal(token, Context::default()),
                Reason::PrefixOutOfRange,
                "{token}"
            );
        }
    }

    /// A `/` after something with no address shape is a path or a
    /// fraction. Reporting it would put every `src/v1` and every `1/2`
    /// in the report.
    #[test]
    fn a_slash_after_a_non_address_is_not_a_block() {
        for token in ["1/2", "10.0/8", "1.2.3/24", "ab/16"] {
            assert!(read(token, Context::default()).is_none(), "{token}");
        }
    }

    /// A dotted run whose groups are not decimal is not an address and
    /// not an ambiguity either. `fe.ff` is two hex bytes in a dump, and
    /// a report that named it would name every one of them.
    #[test]
    fn a_dotted_run_that_is_not_decimal_is_silent() {
        for token in ["a.b", "fe.ff", "10..1", "1.2.c.4", "."] {
            assert!(read(token, Context::default()).is_none(), "{token}");
        }
    }

    // -- CIDR --------------------------------------------------------

    #[test]
    fn an_ipv4_block_reports_its_bounds() {
        let block = block("10.0.0.0/8");
        assert_eq!(block.prefix, 8);
        assert_eq!(block.network, "10.0.0.0");
        assert_eq!(block.broadcast.as_deref(), Some("10.255.255.255"));
        assert_eq!(block.hosts, "16777216");
    }

    /// Host bits set below the prefix: the block is still the block, and
    /// the network address says so.
    #[test]
    fn a_block_written_with_host_bits_keeps_both_forms() {
        let Some(Reading::Address {
            normalized, block, ..
        }) = read("10.1.2.3/24", Context::default())
        else {
            panic!("an address");
        };
        assert_eq!(normalized, "10.1.2.3/24");
        assert_eq!(block.expect("a block").network, "10.1.2.0");
    }

    /// The two shifts that wrap if they are done the obvious way.
    #[test]
    fn the_widest_and_narrowest_blocks_are_arithmetically_right() {
        let all = block("0.0.0.0/0");
        assert_eq!(all.hosts, "4294967296");
        assert_eq!(all.broadcast.as_deref(), Some("255.255.255.255"));
        let one = block("192.0.2.1/32");
        assert_eq!(one.hosts, "1");
        assert_eq!(one.network, "192.0.2.1");
    }

    /// 2^128 is one more than `u128::MAX`, so it is the one count this
    /// cannot compute and the one most likely to be wrong.
    #[test]
    fn the_whole_ipv6_space_counts_correctly() {
        let all = block("::/0");
        assert_eq!(all.hosts, "340282366920938463463374607431768211456");
        assert_eq!(all.broadcast, None, "IPv6 has no broadcast address");
        assert_eq!(all.last, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
        assert_eq!(
            block("2001:db8::/32").hosts,
            "79228162514264337593543950336"
        );
    }

    #[test]
    fn a_block_is_classified_by_its_network_address() {
        let Some(Reading::Address { class, .. }) = read("127.0.0.0/8", Context::default()) else {
            panic!("an address");
        };
        assert_eq!(class, Class::Loopback);
    }

    /// A hazard inside a block is still a hazard: masking it would
    /// resolve the octal question the refusal exists to leave open.
    #[test]
    fn an_octal_hazard_in_a_block_is_still_refused() {
        assert_eq!(
            refusal("010.0.0.0/8", Context::default()),
            Reason::OctalHazard
        );
    }

    // -- the vocabulary ----------------------------------------------

    #[test]
    fn every_named_kind_and_class_parses_back() {
        for name in Kind::ALL {
            let kind = Kind::parse(name).expect(name);
            let rendered = serde_json::to_value(kind).expect("serializes");
            assert_eq!(rendered, serde_json::json!(name));
        }
        for name in Class::ALL {
            let class = Class::parse(name).expect(name);
            let rendered = serde_json::to_value(class).expect("serializes");
            assert_eq!(rendered, serde_json::json!(name));
        }
        assert!(Kind::parse("ipv5").is_none());
        assert!(Class::parse("public").is_none());
    }

    /// The human line prints `Class::name` and the JSON prints serde's
    /// rendering. They are two spellings of one vocabulary, so a class
    /// added to one and not the other has to fail here rather than on
    /// somebody's stderr.
    #[test]
    fn the_printed_name_of_a_class_is_the_name_serde_writes() {
        for name in Class::ALL {
            let class = Class::parse(name).expect(name);
            assert_eq!(class.name(), name);
            assert_eq!(serde_json::to_value(class).expect("serializes"), name);
        }
    }

    #[test]
    fn an_address_key_is_recognised_by_its_last_segment() {
        assert!(Context::from_key(Some("server.remote_ip")).address);
        assert!(Context::from_key(Some("bind-address")).address);
        assert!(Context::from_key(Some("DB_HOST")).address);
        assert!(!Context::from_key(Some("description")).address);
        assert!(!Context::from_key(None).address);
        assert!(Context::from_key(Some("app.version")).version);
        assert!(!Context::from_key(Some("app.name")).version);
    }
}
