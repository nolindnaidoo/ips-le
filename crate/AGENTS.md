# ips-le (CLI) — engineering standards

This is the source of truth for how code in `crate/` is written, tested
and reviewed. It applies to every contributor, human or AI-assisted.
[SPEC.md](SPEC.md) defines the product behaviour — the refusals, the
classes, the exit codes; this file is how the code gets there.

## What this project is

The command-line and MCP frontend of IPs-LE: get every network address
out of a tree, normalized and classified, so a person can check a
boundary. Nothing is judged, rewritten, or looked up — see SPEC.md,
"Non-goals".

**The reader is not the author.** Someone checking a firewall
allow-list against a change request, or a fetch path against an SSRF
review, is an auditor. They usually have no checkout and never have the
editor open. Every decision below follows from that.

**Status: 0.1.0.** Core functionality, deliberately not a hardened 1.0.
The known limits are in SPEC.md, "Known limits in 0.1.0" — they are
written down, not undiscovered.

## Layout

```
crate/src/
├── extract/     pure: the scanner, the policy layer, the seven key
│                readers, positions. No filesystem, no network.
├── walk.rs      ignore-aware tree walking
├── scan.rs      one file end to end — the only path either surface calls
├── cli.rs       the terminal surface
└── mcp/         the agent surface
```

Inside `extract/`:

```
scanner.rs   bytes  → candidate runs      (format-independent)
<format>.rs  bytes  → key spans           (json yaml toml ini env csv log)
policy.rs    run    → address or refusal  (the decision layer)
locate.rs    joins the three
```

- **`extract/` touches no filesystem and no network.** It takes
  document text and returns findings, so the whole decision layer tests
  from a string — no temp directories, no flake, no sockets. A
  `std::fs` or a `std::net::TcpStream` appearing there is a bug.
  `std::net::{Ipv4Addr, Ipv6Addr}` is *parsing*, not networking, and is
  the point.
- **`scan.rs` and `walk.rs` are the only modules allowed to touch the
  filesystem.**
- **Both surfaces are one implementation.** `cli.rs` and `mcp/` both
  call `scan.rs`. A surface that grows its own copy of a rule is a bug,
  and a contract test asserts the two return identical reports for the
  same tree.
- Keep modules flat. No layers, registries, managers, or services. No
  trait with a single implementation.

## Decisions already made (do not relitigate)

- **The scan runs over the bytes of every document, whatever its
  format.** This is the opposite of the sibling extractors and it is
  the crate's founding decision. A network address is almost never a
  value — it is inside one (`postgres://10.0.0.5:5432/app`) or inside a
  log line, which has no values at all. A parse-tree walk over leaf
  values would miss every one of them. The format parse contributes
  **only the key path**, which is why an unrecognised format costs a
  locator and never an address.

- **Refusals are the product, not an error path.** Six named reasons,
  each for a place where two answers are equally defensible. A refusal
  is a finding: it does not move the exit code without `--strict`, and
  **no filter may hide one** — `--class private` still shows the octal
  hazard, because that is the finding a filtered report would most
  regret dropping. Turning any refusal into an answer is a behaviour
  change that needs a CHANGELOG entry and a very good reason.

- **`010.1.1.1` is never resolved, on either stream.** It is 8.1.1.1 to
  a resolver that reads a leading zero as octal and 10.1.1.1 to one
  that reads it as decimal; both exist in shipped software, which is
  what makes it an SSRF bypass. A contract test greps the output for
  the readings it must not contain.

- **A decoded form appears only next to its flag.** `2130706433`
  carries `127.0.0.1` inside the `integer_form` refusal message and
  nowhere else. The moment it appears as a `normalized` value, the flag
  is gone and only the claim is left.

- **Normalization is `std::net`'s `Display`, pinned by fixtures.** It
  implements RFC 5952 correctly today, including the rules that are
  easy to get wrong — longest zero run rather than first, no
  compression of a single group, dotted tail for IPv4-mapped. The
  fixtures pin those against the RFC's own examples rather than against
  this code, so a future standard-library change fails a test here
  rather than a diff in someone's audit.

- **No `ipnet`, no `cidr`, no `regex`.** `std::net` parses both
  families and rejects a leading zero (so the standard library cannot
  resolve an octal hazard behind our back). CIDR arithmetic is a mask,
  an AND and an OR over a `u32` or a `u128`. And the shapes here —
  `::` compression, six hex pairs, a dotted quad that may be a version
  — are decided by a hand-written scanner because an IPv6 regex is a
  known way to be confidently wrong.

- **`jsonc-parser` is the one parser dependency**, for JSON alone. A
  minified document is one line, so a line-oriented key reader answers
  nothing useful for exactly the file where a key path is most wanted.
  Every other format is read line by line in its own module — which is
  why there is one parser here and not six.

- **The scanner is where noise is controlled, not the policy layer.** A
  log file is mostly timestamps, durations, ports and hashes, built
  from the same alphabet as an address. If `2026:10:30:00` reaches
  `policy::read`, the honest answer is `malformed_address`, and a
  refusal on every line of every log makes the vocabulary worthless.
  So the scanner declines it. Any new "we should refuse X" instinct
  should be checked against `ips-le ../numbers-le/crate/src` first: an
  address-free codebase should produce a handful of refusals, not
  hundreds.

- **stdout is protocol, stderr is human. There is no `--json` flag.**
  One mode, nothing to misremember, and the human summary is a
  projection of the same reports so the two cannot drift.

- **Every field is always present in a finding, nulls included.** A
  consumer writes one reader and never decides whether an absent key
  and a null key mean different things. `schema: 1` is its own field
  for the same reason.

- **A format name is lenient; a filter name is not.** An unrecognised
  `--format` falls back to the byte scan, because the bytes do not
  care. An unrecognised `--kind` or `--class` is an error, because
  silently reporting everything would answer a question nobody asked.

## Control-flow style

Flat over nested, guards over branches:

- **No statement-position `else`.** Guard clauses and early `return`
  (`if !ok { return ... }` / `let Some(x) = ... else { return }`), then
  fall through to the happy path.
- **Value-position `if/else` is fine** — it is Rust's ternary.
- **`match` is fine and preferred** over any chain of condition tests
  on the same value; use match guards instead of `if/else` inside arms.
- Prefer combinators where they read cleanly: `bool::then_some`,
  `Option::map/filter/is_some_and`, `?`.
- No nesting deeper than two levels inside a function; extract a named
  helper instead.

## Hard rules

- **No inline `#[allow(...)]`.** Either fix the lint or add a visible,
  commented relaxation to `[lints.clippy]` in `Cargo.toml`. There are
  none today, and that is the state to keep.
- **Clippy pedantic, deny warnings.** `cargo clippy --all-targets --
  -D warnings` must pass.
- **`unsafe` is forbidden crate-wide** (`[lints.rust]`).
- **`overflow-checks = true` in release.** The CIDR arithmetic shifts
  by a prefix length, and a wrong answer that wraps silently is the
  failure mode a tool whose whole promise is "never guess" cannot have.
- **No network, ever.** Not a DNS lookup, not a connect, not a WHOIS,
  not telemetry, not behind a flag. A dependency that could open a
  socket does not belong in this crate.
- **Dependencies are a cost.** Four today. Justify every addition in a
  Cargo.toml comment; prefer the standard library.
- **Strict parsing, never silent defaults.** Bad flags and unknown
  filter names are errors with actionable messages.
- **Refuse rather than guess.** Two defensible readings means a named
  refusal, never a picked one.
- **Refusals speak the caller's vocabulary.** An MCP caller has no
  command line; no message on that surface mentions a flag, and a test
  greps for `--`.

## Testing

- **`extract/` is pure, so everything in it tests from a string.** If
  something there is hard to test, the design is wrong.
- **The corpus is embedded** (`fixtures/`, `include_str!`), so
  `cargo test` on the published tarball runs every case and the README
  claims are checkable rather than trusted. Four sections, each
  guarding a different silent failure: `normalization` against RFC
  5952, `classification` covering all ten classes and all four kinds,
  `ambiguity` where **every case expects a refusal**, and `documents`
  pinning a real file per format with positions and key paths.
- **A new refusal reason adds three things**: a case in `ambiguity`, a
  line in `tests/contracts.rs`, and a row in SPEC.md's refusal table.
  Tests assert the enum and the corpus cover each other, so a reason
  with no case fails the build.
- **Exit codes belong in `tests/contracts.rs`.** They are the API —
  callers branch on them — so they are pinned by tests that drive the
  built binary. Nothing there needs a network or a privileged
  operation.
- **Anything needing a document larger than an editor opens is
  `tests/scenarios.rs`**, gated behind `IPS_LE_SCENARIOS`. A skipped
  scenario is never reported as a pass.
- **Every bug fix ships with a regression test** that fails before the
  fix.
- Tests are deterministic: no clocks, no randomness, no network.

## Verification — the definition of done

```bash
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
```

A change is not done because it compiles; it is done when it is tested,
linted, documented where behaviour changed (README / SPEC / CHANGELOG /
this file), and honest — claims in docs must match the code.
