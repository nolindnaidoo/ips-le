# Instructions for AI coding assistants

Read [AGENTS.md](AGENTS.md) first — it is the engineering-standards
document for this crate and the source of truth for layout, control-flow
style, the settled decisions, testing requirements and the definition of
done. [SPEC.md](SPEC.md) defines the product behavior. AGENTS.md wins on
any conflict.

- Before declaring any change complete, run exactly what CI runs:
  `cargo fmt --all --check`,
  `cargo clippy --all-targets -- -D warnings`,
  `cargo test --locked`. All three must pass.
- Never add an inline lint attribute — not `#[allow]`, not `#[expect]`,
  not a `cfg_attr` carrying one, not the inner `#![...]` form. There are
  none today and that is the state to keep. The `policy` job greps for
  all of those spellings across `src/` **and** `tests/`; it used to grep
  for `allow` alone, and an `#[expect(dead_code)]` sat under a green
  build because of it.
- New logic goes in `extract/` when it is pure — it must then be unit
  tested, and it carries a **75% line coverage floor per module**. A
  `std::fs` or a `std::net::TcpStream` there is a bug.
  `std::net::{Ipv4Addr, Ipv6Addr}` is *parsing*, not networking.
- **No network, ever.** Not a DNS lookup, not a connect, not a WHOIS,
  not telemetry, not behind a flag. A dependency that could open a
  socket does not belong here.
- **Refuse rather than guess.** Two defensible readings means a named
  refusal, never a picked one. A test that passes by resolving something
  that should have been refused is the bug this family exists to prevent.
- **Refusals speak the caller's vocabulary.** An MCP caller has no
  command line, so no message on that surface names a flag; a test greps
  for `--`.
- **`overflow-checks` stays on in release.** The CIDR arithmetic shifts
  by a prefix length, and a silently wrapped answer is exactly the
  failure a tool promising "never guess" cannot have.
- **No reachable panic.** No `unwrap`, no `expect`, no panicking index,
  no arithmetic an input can overflow — every fallible path returns
  `Option` or `Result`. The only sanctioned `expect` is serialising a
  report or envelope in `cli.rs` / `mcp/`, where the types are structs
  of strings, integers, enums, `Option` and `Vec` — no map with a
  non-string key, no float — so `serde_json` cannot fail and the
  `expect` states that invariant rather than hiding a failure. Every
  test run serialises the whole corpus through them. A new one needs the
  same argument.
- **A fallback for an impossible case is a wrong answer waiting.**
  `unwrap_or` on a branch an earlier check made unreachable survives the
  day that check moves, and then answers with a plausible number.
  Restructure so the check and the conversion are one step — `cidr_v4`
  narrows the prefix to a `u8` *as* the range test, and `mac_octets`
  returns the octets it proved. `checked_shl(...).unwrap_or(0)` is not
  this: a prefix of 0 asks to shift by the full width and 0 is the mask
  it is asking for, which is why it carries a comment saying so.
- The gated suites are opt-in and CI sets them: `IPS_LE_BUDGET=1`,
  `IPS_LE_FUZZ_SECONDS`, `IPS_LE_FUZZ_SEED`, `IPS_LE_SCENARIOS=1`. A
  skipped case says so by name; a skip is never reported as a pass.
- Write a regression test for every bug you fix, and **observe it fail
  before the fix** rather than assuming it would have. Run the binary
  against a real tree, not only the suite.
