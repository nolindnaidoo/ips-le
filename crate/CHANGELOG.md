# Changelog

The Rust CLI and MCP server for ips-le.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-08-15

### Fixed

- **A `.tsv` row is keyed cell by cell.** `.tsv` named the comma reader,
  so a tab row was one cell and every address on it reported
  `[row][0]` — three different addresses on one line all claiming the
  same column. A coordinate is a locator a reader acts on, so a
  plausible wrong one is worse than none. Checked against Python's
  `csv.reader(delimiter='\t')`.

### Added

- `tsv` is a format in its own right: it resolves, names itself in a
  report, and is offered in the MCP schema.

- A contract test over the built binary, observed failing before the
  fix, pinning that each cell is keyed by its own column.

### Unchanged, deliberately

- `.conf` and `.cfg` keep the INI reader. Two sibling crates dropped
  them because their INI readers found keys in free-form prose; this
  one does not — the same sentence gives the same address and the same
  absent key whether it is read as `ini` or as text, and that was
  measured before deciding.

## [0.1.2] - 2026-08-15

### Fixed

- **The crates.io page shows the icon and the demo.** Both lived only in
  the repository README, and that file is not the one `cargo publish`
  ships — the published README is this directory's. A relative path
  would not have fixed it: the crate is published from `crate/`, so
  crates.io resolves a relative link against `path_in_vcs` and looks for
  the assets below the crate directory rather than beside it. Both are
  absolute URLs, which every surface renders.

## [0.1.1] - 2026-08-14

### Fixed

- **An address in a trailing comment no longer inherits the key beside
  it.** `bind: 10.0.0.5 # was 10.0.0.9` reported *both* addresses under
  `bind`, so a config was described as binding to an address it does not
  bind to — a false positive with a name attached, in the one column an
  allow-list review relies on. All four line readers spanned a value to
  the end of the raw line: YAML and TOML stripped the comment to parse
  and then measured the unstripped line, and INI and `.env` did not strip
  at all. A whole-line comment was always reported correctly; the two
  forms agree now.

  The strip is shared and **quote-aware**, so `bind = "10.0.0.5 # nope"`
  stays one address and `PASSWORD=a#b` keeps its `#`. INI reads `;` and
  `#`; YAML, INI and `.env` need the marker to open the line or follow
  whitespace, while TOML ends a value at any unquoted `#`.

  Only the `key` field moves. No address is added, removed or
  repositioned by this change.

  Two smaller corrections ride along, both the same defect: an INI
  section header with a trailing comment (`[cache] ; note`) now sets the
  section instead of being read as a key line, and a YAML comment marker
  preceded by a tab is now a comment as one preceded by a space always
  was.

- **A CIDR prefix of digits is out of range however long it is.**
  `10.0.0.0/999` answered `prefix_out_of_range` and `10.0.0.0/65536`
  answered `malformed_address` — the same mistake named two ways,
  decided by whether the digits happened to fit a `u16` before anything
  judged them. A run of digits is a prefix; whether it fits the family
  is the range question. Only a prefix that is not digits at all
  (`/abc`, `/`) is malformed now.

  **No output moves.** Neither surface can reach the branch: the scanner
  attaches at most three digits to a `/` and stops at a fourth, so
  `/65536` never becomes a block candidate on the CLI or through
  `extract_ips` — it is two separate runs and no finding. The decision
  layer was inconsistent with itself about a class of input, which stops
  being harmless the day the scanner's cap changes.

- **The MCP server no longer ends a session over a frame that is not
  UTF-8.** One such line exited 2 and took every frame that would have
  followed with it, while a line that was not JSON was skipped and the
  loop went on — two policies for one class of input, and the harsher one
  fired on the case a client is likeliest to produce by accident. A
  malformed frame is dropped either way: it carries no id, so there is
  nobody to report it to. A genuine stream failure still stops the
  server, which is the case that would otherwise spin.

### Changed

- **One sentence describes this crate everywhere it is described.** The
  `description` in `Cargo.toml`, the line under the title in
  `README.md`, and the entry on letools.dev had drifted into three
  paraphrases, so the crate a reader met on crates.io was not obviously
  the one they met on the site. Nothing about the tool moved.

- `crate/SPEC.md` states the comment rule per dialect, and the corpus
  pins it: `network.yaml`, `network.toml`, `network.ini` and
  `network.env` each carry a trailing comment holding an address, so a
  reader that started attributing one again fails a test.

- **README.md's sample output is now the tool's own**, checked against a
  real run by `tests/contracts.rs`. It printed four of eight findings as
  though that were the whole answer, and had gone stale against the
  fixture it names — a plausible report nobody re-ran, which is the
  thing this crate exists to stop. Its `AGENTS.md` link points at the
  repository rather than relatively, because that file is deliberately
  excluded from the published package and the relative link was broken
  for anyone reading from crates.io or an unpacked tarball.

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
  question. **A path the walk cannot open never moves it**: a locked
  directory is carried as a `skipped` report line — named on stderr,
  present in the JSON, failing `--strict` — so one unreadable directory
  cannot delete the audit of everything readable beside it. Exit 2 stays
  what it is for: a question that was malformed.

- **Report paths spelled with `/` on every platform**, so a report
  produced on Windows and one produced on Linux describe the same tree
  and a consumer never has to know which machine wrote it.

### Verification

Beyond the embedded corpus, four hardening suites and a coverage matrix,
each gated so a bare `cargo test` stays fast and each with its own CI
job:

- `tests/hazards.rs` — a byte-order mark, bytes that are not UTF-8, a
  UTF-16 log, a FIFO, a symlink loop, permission-denied paths, a path
  over 260 characters, an empty file, a several-megabyte minified JSON
  document, a log with no trailing newline. Built at runtime; a case the
  platform cannot express is skipped by name.
- `tests/platform.rs` — one path separator everywhere, case folding,
  reserved Windows names, CRLF, stdin, `TZ` independence.
- `tests/fuzz.rs` — generated input against the scanner's three
  splitting rules, seeded from `IPS_LE_FUZZ_SECONDS` /
  `IPS_LE_FUZZ_SEED`. Every document carries an octal hazard whose two
  readings may never appear on either stream.
- `tests/budget.rs` — a wall-clock ceiling and three linearity checks,
  including 20,000 addresses on one non-ASCII line: the shape that made
  the position index quadratic before it kept checkpoints (62 s → 0.30 s).
- `tests/coverage_matrix.rs` — every kind, class, refusal reason and
  format reader reachable from a real fixture, and nothing produced that
  the vocabulary does not name.

### Deliberately not included

No DNS resolution, no geolocation, no network access of any kind, no
verdict, no rewriting. See [SPEC.md](SPEC.md), "Non-goals".

[0.1.0]: https://crates.io/crates/ips-le/0.1.0
[0.1.1]: https://crates.io/crates/ips-le/0.1.1
[0.1.2]: https://crates.io/crates/ips-le/0.1.2
[0.2.0]: https://crates.io/crates/ips-le/0.2.0
