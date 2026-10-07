# Changelog

All notable changes to IPs-LE will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file covers the **VS Code extension**. The Rust CLI in `crate/` is a
separate product on its own cadence and keeps its own
[CHANGELOG](crate/CHANGELOG.md). The entries below 1.0.0 describe this
repository while it held the CLI alone.

## [1.1.0] - 2026-10-07

### Added

- A rating prompt. On the 3rd successful use, one notification asks whether
  you would rate the extension, with *Rate*, *Later* and *Don't Ask Again*.
  *Rate* opens the registry your copy was installed from: the VS Code
  Marketplace or Open VSX. *Later*, or dismissing it, asks once more on the
  20th use; that second ask is the last. It never appears on activation or
  after a failed run, and it is never shown if you have set
  `notificationsLevel` to `important` or `silent` yourself. The answer
  follows you through Settings Sync. Translated into all 12 locales.
- Scan a folder or the whole workspace. `IPs-LE: Scan Workspace for Addresses`
  reads every file in the workspace from disk. `IPs-LE: Scan Folder for Addresses`
  does the same for one folder, from the command palette or from a folder in
  the Explorer. Files are read from disk, so an unsaved edit is not seen. The
  report opens with a table of every file that holds an address, then has
  a section per file, and ends with a line for each thing the scan left
  unread.
- A scan skips three things by default, each with its own switch:
  dependency folders, build output, caches and lockfiles
  (`ips-le.workspace.scanUseDefaultExcludes`), whatever the project's
  `.gitignore` files skip (`ips-le.workspace.scanRespectGitignore`), and
  images, fonts, archives and other files that are not text
  (`ips-le.workspace.scanSkipBinaryFiles`). `ips-le.workspace.scanExcludes`
  skips more, and `ips-le.workspace.scanAlwaysInclude` reads a path whatever
  the switches say. The report names which of these were on.
  `ips-le.workspace.scanPatterns` chooses the files to read in the first
  place.
- `ips-le.workspace.scanMaxFiles` caps how many files are read and
  `ips-le.workspace.scanMaxResults` caps how many addresses are listed. A
  file over the safety size, or one that is not UTF-8 text, is left unread,
  and the report says how many were.
- Runs that could not be read are counted per file in a scan, not listed.
  `ips-le.workspace.scanIncludeRefusals` lists each one, and
  `ips-le.workspace.scanProblemsEnabled` also shows them in the Problems
  panel. Both are off by default, so a project's report stays short.
- The positions settings apply to a scan as they do to Extract.
- Positions are now a setting. `ips-le.showPositions` decides whether the
  output gives the line and column of each address, and
  `ips-le.clipboardIncludesPositions` decides the same for the copy on the
  clipboard. Both are on by default, so the output is what it was.

### Changed

- No command is bound to a key by default any more. The one default this
  extension shipped sat on a key the editor, the system or another LE
  extension already used. Every command can still be given a key under
  Keyboard Shortcuts.

## [1.0.1] - 2026-10-04

### Fixed

- The Open VSX links and the Open VSX downloads badge in the README and the
  npm README pointed at a namespace the listing has left, so they led nowhere.
  The listing is under `nolindnaidoo` now, and so are they.

### Removed

- The Zed extension in `zed/`, with the CI job that built it and the workflow
  that synced it. It was never listed in Zed's registry.

## [1.0.0] - 2026-10-03

### Added

- **The VS Code extension.** `IPs-LE: Extract Addresses` lists every IPv4 and
  IPv6 address, CIDR block and MAC address in the active document by kind,
  with its line and column, its key path, its canonical form — RFC 5952 for
  IPv6 — and its class, a CIDR block's span and size, and every run it could
  not read as an address with the reason. `ips-le.kinds` and `ips-le.classes`
  narrow the addresses; refusals are always shown.
- **The MCP server in the VSIX and on npm** as `ips-le-mcp`: the same
  `extract_ips` tool the Rust CLI serves, answering identically.
- **The engine is a port of the crate's**, with Rust std's address parsing and
  RFC 5952 formatting and jsonc-parser's JSON reading transcribed, held to the
  crate by the shared corpus, a differential that feeds both servers thousands
  of generated documents in every format — broken JSON included — and a check
  that both servers define the tool identically.
- Localized into twelve languages: the manifest and every runtime string.
- A Zed extension that runs the MCP server as a context server.

## [0.1.1] - 2026-08-14

What changed in the crate is in
[`crate/CHANGELOG.md`](crate/CHANGELOG.md). This section is the
repository around it.

### Added

- **A terminal demo** at [`assets/demo.gif`](assets/demo.gif), driving
  the real binary over the files in [`assets/demo/`](assets/demo/).
  [`assets/demo.tape`](assets/demo.tape) is the `vhs` script that
  produced it, so `cd assets && vhs demo.tape` reproduces the recording
  rather than leaving an artifact nobody can regenerate. Both sit above
  `crate/`, where `cargo package` cannot reach them.

### Changed

- **New icon artwork.** All sixteen tools were redrawn in one style, so
  the family reads as one set wherever the cards sit side by side. The
  framing is unchanged — the drawing fills 65.8% of an 800×800 canvas
  and every smaller size is derived from that one file rather than drawn
  again.

### Fixed

- **The README's images resolve away from GitHub.** They were repository
  paths, which crates.io and every other renderer resolves against its
  own origin, so the demo and the icon were broken everywhere this file
  is read that is not this repository. They are absolute URLs now.

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

[0.1.0]: https://crates.io/crates/ips-le/0.1.0
[0.1.1]: https://crates.io/crates/ips-le/0.1.1
