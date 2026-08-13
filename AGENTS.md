# AGENTS.md — IPs-LE

Technical source of truth for this repository. [README.md](README.md) is
the user-facing doc; this file is for anyone, human or agent, changing
the code.

**This repo hosts one product**: the Rust CLI and MCP server in
[`crate/`](crate/). There is no extension beside it, so unlike the
two-frontend siblings there is no shared corpus to keep in parity and no
`parity` or `differential` CI job — those are deliberately absent rather
than present and vacuous, and they arrive with the extension if one ever
does.

## Read this first

**[`crate/AGENTS.md`](crate/AGENTS.md) is the engineering standard**:
layout, control-flow style, the decisions already made, the hard rules,
the testing requirements and the definition of done. It wins over this
file for anything inside `crate/`, which is everything.
[`crate/SPEC.md`](crate/SPEC.md) defines the product behaviour — the
refusals, the classes, the exit codes, the non-goals — and
`crate/AGENTS.md` wins on any conflict between them.

| Question | File |
|---|---|
| How should this code be written? | [`crate/AGENTS.md`](crate/AGENTS.md) |
| What is this tool allowed to say? | [`crate/SPEC.md`](crate/SPEC.md) |
| What does the user see? | [README.md](README.md) · [`crate/README.md`](crate/README.md) |
| What changed? | [CHANGELOG.md](CHANGELOG.md) · [`crate/CHANGELOG.md`](crate/CHANGELOG.md) |

## Gates

```bash
cd crate
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
```

All three must pass. A change is not done because it compiles; it is
done when it is tested, linted, documented where behaviour changed, and
honest — a claim in a README or a help text that the code does not back
is a defect.

CI runs those three on macOS, Windows and Linux, and adds five jobs that
exist because something real got through a green suite. Each one is
gated locally so a bare `cargo test` stays fast:

```bash
cargo test --test hazards                                  # byte- and filesystem-level inputs
cargo test --test platform                                 # what differs by operating system
IPS_LE_FUZZ_SECONDS=60 cargo test --test fuzz -- --nocapture
IPS_LE_BUDGET=1 cargo test --test budget -- --test-threads=1 --nocapture
cargo test --test coverage_matrix -- --nocapture
IPS_LE_SCENARIOS=1 cargo test --test scenarios
```

Coverage is a **floor**, never lowered to make a build pass: 75% of
lines per module in `crate/src/extract/`, enforced per module rather
than on the total, because a total hides one module sliding while the
others carry it.

## Non-negotiables

The full list is in [`crate/AGENTS.md`](crate/AGENTS.md). The ones worth
repeating where a first-time reader will see them:

- **Refuse rather than guess.** Two defensible readings means a named
  refusal, never a picked one. Turning any refusal into an answer is a
  behaviour change that needs a CHANGELOG entry and a very good reason.
- **`010.1.1.1` is never resolved, on either stream.** A contract test
  and the fuzz suite both grep the output for the readings it must not
  contain.
- **No network, ever.** Not a DNS lookup, not a connect, not a WHOIS,
  not telemetry, not behind a flag. A dependency that could open a
  socket does not belong in this crate.
- **No inline `#[allow(...)]`.** Fix the lint, or add a visible
  commented relaxation to `[lints.clippy]` in `crate/Cargo.toml`. A CI
  job greps for it.
- **`unsafe` is forbidden crate-wide**, tests included.
- **Guard clauses over nesting**, no statement-position `else`, nothing
  deeper than two levels inside a function.
- **Comments explain *why*, never what.**
- **Every bug fix ships with a regression test** that fails before the
  fix.
- **Never report success you did not achieve.** Run the check; do not
  infer it.
- Commits are conventional (`fix:`, `feat:`, `docs:`…), imperative, and
  enforced by a hook and by CI.

## Repository shape

```
crate/          the CLI + MCP server, its own AGENTS.md and SPEC.md
.github/        workflows, dependabot, CodeQL
```

Everything else at the root — `.editorconfig`, `.gitattributes`,
`.githooks/`, the assistant rule files — is family scaffolding held
byte-identical across the sibling repos. Change it here only if it is
being changed everywhere.
