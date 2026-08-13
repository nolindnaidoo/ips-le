# CLAUDE.md

[AGENTS.md](AGENTS.md) is the technical source of truth for this repo, and it
routes to [`crate/AGENTS.md`](crate/AGENTS.md) — the engineering standard the
code is held to: control flow, error handling, layout, the decisions already
made, the definition of done. Read it before writing code.

This repository is **crate-only**: the Rust CLI and MCP server in `crate/` and
nothing else. Read [`crate/CLAUDE.md`](crate/CLAUDE.md) and
[`crate/AGENTS.md`](crate/AGENTS.md) for that side; `crate/SPEC.md` defines the
product behaviour. README.md is user-facing.

## Where to look

| Question | File |
|---|---|
| How should this code be written? | [`crate/AGENTS.md`](crate/AGENTS.md) — the standard, the architecture, the invariants |
| What is this tool allowed to say? | [`crate/SPEC.md`](crate/SPEC.md) — refusals, classes, schema, non-goals |
| What does the user see? | [README.md](README.md) |
| What changed? | [CHANGELOG.md](CHANGELOG.md) · [`crate/CHANGELOG.md`](crate/CHANGELOG.md) |

## Gates

```bash
cd crate && cargo fmt --all --check && cargo clippy --all-targets -- -D warnings && cargo test --locked
```

Before a release, also run the gated suites — they are gated so a bare
`cargo test` stays fast, not because they are optional:

```bash
cargo test --test hazards && cargo test --test platform
IPS_LE_FUZZ_SECONDS=60 cargo test --test fuzz -- --nocapture
IPS_LE_BUDGET=1 cargo test --test budget -- --test-threads=1 --nocapture
cargo test --test coverage_matrix -- --nocapture
IPS_LE_SCENARIOS=1 cargo test --test scenarios
```

## Things that will bite you

- **Refusals are the product, not an error path.** Turning one into an answer
  is a behaviour change needing a CHANGELOG entry and a very good reason. No
  filter may hide a refusal, and `010.1.1.1` is never resolved on either
  stream — a contract test and the fuzz suite both grep for the readings it
  must not contain.
- **A decoded form appears only next to its flag.** `2130706433` carries
  `127.0.0.1` inside the `integer_form` refusal message and nowhere else.
- **The scan runs over the bytes, whatever the format.** The format parse
  contributes only the key path. Do not "fix" this into a parse-tree walk; it
  would miss every address inside a connection string and every address in a
  log line.
- **New noise belongs in the scanner, not the policy layer.** If
  `2026:10:30:00` reaches `policy::read`, the honest answer is
  `malformed_address`, and a refusal on every line of every log makes the
  vocabulary worthless. Check any new "we should refuse X" instinct against a
  scan of an address-free codebase first.
- **No network, ever**, and no inline `#[allow(...)]` — CI fails the build on
  the second and there is no way to add the first.
- **Report paths use `/` on every platform.** `crate/tests/platform.rs` pins
  it; a sibling shipped `\` on Windows for a whole release.
- **A long-line performance case must be non-ASCII to mean anything.** The
  position index takes an arithmetic fast path on ASCII, so an ASCII long line
  measures nothing. See `crate/SPEC.md`, "Notes".
- **CI narrows itself on a docs-only push.** `ci-crate.yml` fires on `*.md` and
  the agent instruction files — it has to, because the `policy` job greps them,
  and the filter used to admit only `crate/**` so that gate could run only when
  the files it guards had *not* been touched. On a docs-only push `policy` and
  `commits` run and every Rust job skips. Anything unrecognised, and an
  unreadable diff, counts as code and runs everything.
- **Coverage floors are a backstop, not a target** — well below where the code
  actually is, and never raised to track it: 75% of
  lines per module in `crate/src/extract/`.
- **Every claim must be provable.** Nothing goes in a README or a help text
  unless the code backs it. That governs **behaviour and numbers**, not
  **availability**: an install line for a publish you are about to make is
  **staged, not forbidden**. Write it, and let the release commit be what
  makes it true.
