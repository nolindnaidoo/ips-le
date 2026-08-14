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
├── scan.rs      one file end to end, and `tree()` over a set of paths —
│                the only path either surface calls
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
  same tree. Three places carry rules both surfaces need, and none of
  them may be reimplemented at a call site:
  - `scan::tree` — walk, read, partition, and carry the unreadable
    paths as report lines. A surface that assembles this itself grows
    its own idea of what a binary file is.
  - `Found::survives` — the kind/class filter, including the rule that
    **a refusal survives every filter it cannot be judged by**. It lives
    on the finding rather than on either surface's options because both
    filter, and a second copy is a second chance to drop a refusal.
  - `policy::mac_octets` — the MAC shape *and* its value in one answer,
    so `scanner.rs`'s decision to hold a run together and `policy.rs`'s
    decision to read it cannot disagree.
  - `extract::strip_comment` — where a value ends. Four line readers
    need it, two had grown their own and the other two had none, and
    the result was that a trailing comment handed its addresses the key
    beside them while a whole-line comment did not.
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

- **No inline `#[allow(...)]` and no inline `#[expect(...)]`.** Either
  fix the lint or add a visible, commented relaxation to
  `[lints.clippy]` or `[lints.rust]` in `Cargo.toml`. There are none
  today, and that is the state to keep. The CI `policy` job greps for
  both spellings, the `cfg_attr` wrapping and the inner `#![...]` form,
  across `src/` **and** `tests/` — it used to grep for `allow` alone,
  and an `#[expect(dead_code)]` sat under a green build because of it.
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
- **No reachable panic.** No `unwrap`, no `expect`, no panicking index,
  no arithmetic that can overflow on a path an input can reach. Every
  fallible path returns `Option` or `Result`.

  The exceptions are named, and they are all the same one: serialising
  a report or an envelope (`cli.rs`, `mcp/`). Those types are structs
  of strings, integers, enums, `Option` and `Vec` — no map with a
  non-string key, no float — so `serde_json` cannot fail on them, and
  the `expect` states that invariant rather than hiding a failure. Every
  test run serialises the whole corpus through them, so a field that
  broke it would fail a build rather than a user. Do not add a new one
  without the same argument.

- **A fallback for an impossible case is a wrong answer waiting.**
  `unwrap_or` on a branch an earlier check made unreachable is worse
  than no check: it survives the day the earlier check moves, and it
  answers with a plausible number. Prefer restructuring so the check
  and the conversion are the same step — `cidr_v4` narrows the prefix
  to a `u8` *as* the range test, and `mac_octets` returns the octets it
  proved rather than a `bool` a second function has to re-derive.

  `checked_shl(...).unwrap_or(0)` is not this. A prefix of 0 asks to
  shift by the full width, and 0 is the mask it is asking for — the
  fallback is the answer, and it carries a comment saying so.

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
- Tests are deterministic: no clocks, no randomness, no network. The
  fuzz suite's randomness is seeded and printed, which is the same
  thing.

### The coverage floor

**75% of lines per module in `extract/`**, enforced by the `coverage`
job — per module rather than on the crate total, because a total lets
one module slide while the others carry it. It is a backstop against an untested module rather than a target,
and is not raised to track actual coverage.

```bash
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov
cargo llvm-cov --summary-only
```

`--html` instead of `--summary-only` writes a browsable report to
`target/llvm-cov/html`; CI uploads that same report on every run,
including a failing one, because a failing run is exactly when someone
wants to see which lines are uncovered.

Read the number, not just the threshold. **Every line of production code
in `extract/` is covered.** What the report still shows uncovered is the
`panic!` arm of a test helper and the failure-message argument of an
assertion — lines that run only when a test fails, which is the point of
them. `policy.rs` and `corpus.rs` read just under 100% for that reason alone;
every other module reads 100%. Exact percentages are deliberately not
quoted here — they move with every test added, and a number in a doc
that drifts is the thing this file exists to prevent.

So an uncovered line in production code is a question, not a rounding
error: it is either a live branch nobody tested or a branch nothing can
reach. The first wants a test. The second wants deleting — `read_mac`
carried a `malformed_address` refusal that the shape check made
impossible, and it went — or, if it earns its place, a test calling the
function directly and a comment saying why. `read_cidr`'s non-numeric
prefix is the one that earned it: no document reaches it, because the
scanner attaches only digits to a `/`, but `read` takes a token from
anywhere and the alternative to a named refusal is a block whose prefix
nobody parsed.

### The hardening suites

Four suites and a coverage matrix, each aimed at a failure a green unit
run cannot see, each with its own CI job. They are gated so a bare
`cargo test` stays fast — not because they are optional.

| suite | catches | run it |
|---|---|---|
| `tests/hazards.rs` | inputs a real machine holds and a fixture directory cannot: a byte-order mark, bytes that are not UTF-8, a UTF-16 log, a FIFO, a symlink loop, a locked file or directory, a path over 260 characters, a several-megabyte minified document | `cargo test --test hazards` |
| `tests/platform.rs` | what differs by operating system: the path separator in the report, case folding, reserved Windows names, CRLF, stdin, `TZ` | `cargo test --test platform` |
| `tests/fuzz.rs` | a panic, a hang or a slice off a character boundary in the scanner's three splitting rules — and an octal hazard resolved under generated input | `IPS_LE_FUZZ_SECONDS=60 cargo test --test fuzz -- --nocapture` |
| `tests/budget.rs` | an order of magnitude, and the quadratic class: four times the files, four times the addresses in one file, four times the addresses on one **non-ASCII** line | `IPS_LE_BUDGET=1 cargo test --test budget -- --test-threads=1 --nocapture` |
| `tests/coverage_matrix.rs` | a kind, class, refusal reason or format the tool claims and no fixture reaches — and anything produced that the vocabulary does not name | `cargo test --test coverage_matrix -- --nocapture` |

Three rules they are all held to:

- **A case the platform cannot express is skipped by name.** `SKIPPED
  <case>: <why>` on stderr, never a silent pass. A green run has to say
  what it did not check.
- **A performance case on a long line must be non-ASCII.** The position
  index answers a column arithmetically when the whole document is
  ASCII, so an ASCII long line measures the fast path and nothing else.
  That is exactly how the quadratic in `position.rs` survived a suite
  that had a long-line case — see SPEC.md, "Notes".
- **A marker line, and CI greps for it.** `cargo test <filter>` exits 0
  when the filter matches nothing, so a renamed test passes its job
  silently otherwise. `coverage_matrix` prints counts; the workflow
  greps them.

## Verification — the definition of done
- **Commits are conventional and CI enforces it.** The `commits` job in
  `.github/workflows/ci-crate.yml` validates every pushed commit's subject
  against the same pattern and the same 100-character cap as
  `.githooks/commit-msg`. The hook is opt-in per clone (`git config
  core.hooksPath .githooks`), so `--no-verify` and a fresh checkout defer
  the check to CI rather than escaping it. Scopes may be comma-separated.

All three, exactly as CI runs them, before every push:

```bash
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
```

CI additionally builds on macOS, Windows and Linux, checks the Rust 1.88
minimum version, runs `cargo audit`, runs the no-inline-suppression
policy job, enforces the per-module coverage floor, and runs the five
gated suites above.

A change is not done because it compiles; it is done when it is tested,
linted, documented where behaviour changed (README / SPEC / CHANGELOG /
this file), and honest — claims in docs must match the code.

**A refactor claiming no behaviour change has to prove it**, because the
whole product is a byte-exact report a script branches on. Build the
binary before and after and diff **both streams and the exit code** over
the fixture tree, a forced run of every format, and both MCP tools. A
green test suite is not the proof: the suite pins the cases somebody
thought of, and a refactor is exactly the change that moves a case
nobody did.

## Git identity

Every commit uses the GitHub noreply address:

```
13629544+nolindnaidoo@users.noreply.github.com
```

A real address in commit metadata is public forever — GitHub's API
serves it for any public repo, and scrapers harvest it. Never set a real
address in `user.email`, globally or repo-locally, and never commit with
one. A repo-local `user.email` silently overrides the global one, so
check `git config user.email` in a fresh clone before the first commit.

## Commits

Conventional prefix, imperative subject **under 100 characters**, no
trailing period; the body carries the *why* and the user-visible
consequence, not a list of files touched.

```
type(optional-scope): imperative subject
```

`type` is one of **feat · fix · docs · style · refactor · perf · test ·
build · ci · chore · revert**. A scope is optional and free-form — use
one when it tells the reader where to look. Append `!` for a breaking
change.

One concern per commit. Refactors and behaviour changes travel
separately, and a commit that says "refactor" and moves a byte of output
is the one that costs someone a day. If docs describe the thing you
changed, update them in the same commit — README, SPEC.md, CHANGELOG.md
and this file are part of the code.

Two gates, one rule. The `.githooks/commit-msg` hook rejects a bad
subject before the commit exists — enable it with `git config
core.hooksPath .githooks` — and the `commits` CI job runs the same
check over the pushed range. The hook is skippable with `--no-verify`
and CI is not, so skipping it delays the failure rather than avoiding
it. **They carry the same pattern and must keep carrying it**: a hook
stricter than CI rejects work CI would take, and a hook looser than CI
lets someone push a commit that fails the build.

**CHANGELOG.md is not generated from these.** It is written by hand,
because an entry explaining why a bug mattered is worth more than a list
of subjects.
