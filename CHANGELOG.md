# Changelog

This repository is crate-only, so this file tracks the repository as a
whole; [`crate/CHANGELOG.md`](crate/CHANGELOG.md) tracks the CLI and MCP
server in detail and is the one a consumer of the crate reads.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-08-12

First release. Core functionality, not a hardened 1.0 — the known limits
are written down in [`crate/SPEC.md`](crate/SPEC.md) rather than left to
be discovered. `cargo install ips-le`, or from this repository with
`cargo install --path crate`.

### Added

- **The `ips-le` CLI and MCP server** in [`crate/`](crate/): IPv4, IPv6,
  CIDR and MAC extraction over any text, from a file, a directory or
  stdin. RFC 5952 IPv6 normalization, ten classes, CIDR arithmetic, six
  named refusals, key paths from seven formats, and grep's exit codes.
  Full detail in [`crate/CHANGELOG.md`](crate/CHANGELOG.md).

- **Repository documentation** — this file, [README.md](README.md),
  [AGENTS.md](AGENTS.md), [CLAUDE.md](CLAUDE.md), [GEMINI.md](GEMINI.md)
  and the MIT [LICENSE](LICENSE).

- **Four hardening suites and a coverage matrix**, each named for the
  bug shape it catches, each with its own CI job:

  - `crate/tests/hazards.rs` — a byte-order mark, bytes that are not
    UTF-8, a UTF-16 log, a FIFO, a symlink loop, a permission-denied
    file and directory, a path over 260 characters, an empty file, a
    minified JSON document of several megabytes, and a log with no
    trailing newline. The tree is built at runtime; a case the platform
    cannot express is skipped by name, never passed quietly.
  - `crate/tests/platform.rs` — one path separator on every operating
    system, case folding, reserved Windows names, CRLF logs, stdin, and
    `TZ` independence. The CI job additionally runs the whole suite with
    `TZ` set and unset and diffs the test names and outcomes line for
    line.
  - `crate/tests/fuzz.rs` — time-boxed and seeded from
    `IPS_LE_FUZZ_SECONDS` / `IPS_LE_FUZZ_SEED`, generating hostile text
    aimed at the scanner's three splitting rules. Every generated
    document carries an octal hazard whose two readings may never appear
    in any answer on either stream.
  - `crate/tests/budget.rs` — a wall-clock ceiling on a seeded 500-file
    corpus, plus linearity checks on four times the files, four times
    the addresses in one file, and four times the addresses on one
    non-ASCII line.
  - `crate/tests/coverage_matrix.rs` — every kind, class, refusal reason
    and format reader reachable from a real fixture, and nothing
    produced that those lists do not name. Prints marker lines that CI
    greps for, because `cargo test <filter>` exits 0 when the filter
    matches nothing.

### Fixed

- **One unreadable directory no longer ends the run.** A locked
  directory inside a walked tree turned into a refusal: the run exited 2
  and wrote no reports at all, so an audit of everything readable beside
  it answered nothing. The walk now carries each path it could not open
  as a `skipped` report line — named on stderr, present in the JSON,
  failing `--strict` — and exit 2 stays what it was for: a malformed
  question.

- **Report paths use `/` on every platform.** They were
  `path.to_string_lossy()` straight through, so a report produced on
  Windows would have carried backslashes and no consumer could have
  diffed it against one produced anywhere else.

- **The position index no longer re-counts UTF-16 code units from the
  start of the line on every lookup.** It was quadratic in the addresses
  on a single non-ASCII line and invisible on ASCII, where a byte offset
  *is* a UTF-16 offset. 20,000 addresses on one `café`-laden line took
  62 s and now take 0.30 s; `crate/tests/budget.rs` pins both the
  ceiling and the ratio.

### Documented

- `crate/SPEC.md` now names the four `kind` values it always
  produced, and carries a **Notes** section recording where a quadratic
  hides in a UTF-16 column — including that the same shape is still
  present in a sibling crate.
