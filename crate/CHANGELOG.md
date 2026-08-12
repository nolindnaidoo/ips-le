# Changelog

The Rust CLI and MCP server for ips-le.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-08-12

First release. Core functionality, not a hardened 1.0 — the known
limits are written down in [SPEC.md](SPEC.md) rather than left to be
discovered.

### Added

- **IPv4, IPv6, CIDR and MAC extraction over any text**, from a file, a
  directory or stdin. Every finding carries the text as written, its
  line and column, the normalized form and a class.

- **RFC 5952 IPv6 normalization** — lowercase, no leading zeros, the
  longest zero run compressed (leftmost on a tie, never a single
  group), and a well-known IPv4-embedded prefix keeping its dotted
  tail. This is the reason the tool exists: `2001:0db8::0001` and
  `2001:db8::1` are one address, and a dedupe over raw text says they
  are two. `fixtures/extraction.json` pins the cases against the RFC's
  own examples rather than against this implementation.

- **Ten classes**: `loopback`, `private`, `link-local`, `cgnat`,
  `multicast`, `broadcast`, `reserved`, `documentation`,
  `unique-local`, `global`. An IPv4-mapped IPv6 address takes the IPv4
  class — `::ffff:127.0.0.1` is loopback, and calling it global is the
  exact miss an allow-list review is trying to find.

- **CIDR arithmetic**: `prefix`, `network`, `broadcast` (IPv4 only —
  IPv6 has none), `last` and `hosts`. `hosts` is a decimal string
  because `::/0` holds 2^128 addresses, one more than a `u128` and far
  more than a JSON number can carry.

- **Six named refusals**, and no guesses: `octal_hazard`,
  `ambiguous_version`, `integer_form`, `malformed_address`,
  `prefix_out_of_range`, `mac_ambiguous`. A refusal reports the text,
  names the ambiguity and stops. `010.1.1.1` is never resolved to
  either of its two readings; `2130706433` is decoded only inside the
  refusal that flags it. A refusal does not move the exit code and no
  filter can hide it; `--strict` is the opt-in that makes one fail a
  build.

- **Key paths from seven formats** — `json` (parsed, comments and
  trailing commas accepted), `yaml`, `toml`, `ini`, `env`, `csv`,
  `log` — with everything else scanned the same way and reported
  without one. The byte scan is format-independent, so an unrecognised
  file loses a locator and never an address.

- **Log files as a first-class format**: logfmt `key=value` pairs and
  JSON-per-line both yield keys, and a rotated `access.log.1` resolves
  to `log`. Timestamps, durations and `host:port` pairs are declined by
  the scanner rather than refused by the policy layer, so a log file
  does not produce a page of refusals.

- **A CLI** — `ips-le [options] <file|dir>...`, `--stdin`, `--format`,
  `--kind`, `--class`, `--strict`, `--hidden`, `--no-ignore`. stdout is
  one JSON report per line; stderr is human. No `--json` flag: one
  mode, and the human summary is a projection of the machine one.

- **An MCP server** — `ips-le mcp`, offering `extract_ips` (document
  text, no filesystem) and `ips_le_scan` (a path). Both return
  `{ ok, data, diagnostics, meta }`, where `ok` means the scan ran.

- **Exit codes following grep**: 0 found, 1 none found, 2 malformed
  question.

### Deliberately not included

No DNS resolution, no geolocation, no network access of any kind, no
verdict, no rewriting. See [SPEC.md](SPEC.md), "Non-goals".
