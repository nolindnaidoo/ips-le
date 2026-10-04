<p align="center">
  <img src="src/assets/images/icon.png" alt="IPs-LE Logo" width="96" height="96"/>
</p>
<h1 align="center">IPs-LE: One Address, One Spelling</h1>
<p align="center">
  <b>Find every IP address, CIDR block and MAC in a document, normalized and classified, and refuse the ambiguous ones by name</b><br/>
  <i>IPv4 · IPv6 (RFC 5952) · CIDR · MAC — no DNS, no lookups, no sockets</i>
</p>

<p align="center">
  <a href="https://marketplace.visualstudio.com/items?itemName=nolindnaidoo.ips-le">
    <img src="https://img.shields.io/badge/Install%20from-VS%20Code-blue?style=for-the-badge&logo=visualstudiocode" alt="Install from VS Code Marketplace" />
  </a>
  <a href="https://open-vsx.org/extension/nolindnaidoo/ips-le">
    <img src="https://img.shields.io/open-vsx/dt/nolindnaidoo/ips-le?style=for-the-badge&label=Open%20VSX&color=blue" alt="Open VSX downloads" />
  </a>
  <a href="https://www.npmjs.com/package/ips-le-mcp">
    <img src="https://img.shields.io/npm/v/ips-le-mcp?style=for-the-badge&label=MCP%20server&color=blue&logo=npm" alt="ips-le-mcp on npm" />
  </a>
  <a href="https://crates.io/crates/ips-le">
    <img src="https://img.shields.io/crates/v/ips-le?style=for-the-badge&label=Rust%20CLI&color=blue&logo=rust" alt="ips-le on crates.io" />
  </a>
  <a href="https://letools.dev/tools/ips-le">
    <img src="https://img.shields.io/badge/LE%20Tools-letools.dev-blue?style=for-the-badge" alt="LE Tools" />
  </a>
</p>

---

> **Useful?** A star or rating is how other developers find it —
> [★ GitHub](https://github.com/nolindnaidoo/ips-le) ·
> [★ Open VSX](https://open-vsx.org/extension/nolindnaidoo/ips-le/reviews) ·
> [★ Marketplace](https://marketplace.visualstudio.com/items?itemName=nolindnaidoo.ips-le&ssr=false#review-details)

## What it does

An allow-list review asks whether `2001:0db8::0001` is already on the list. The list says `2001:db8::1`. A diff of the raw text calls them two addresses; they are one.

Open a document, press `Ctrl+Alt+A` (`Cmd+Alt+A` on Mac), and every IPv4 and IPv6 address, CIDR block and MAC address in it is listed by kind with its line and column, the key it sits under, its canonical form and what it is for — loopback, private, link-local, documentation and the rest. A CIDR block comes with its network, its last address and how many addresses it holds. The report opens beside the editor. Works in VS Code and in VS Code–based editors like Cursor and VSCodium (installable from Open VSX).

- **Reviewing a config or an allow-list** — one spelling per address, and the private ones named as private
- **Reading a log** — every peer and upstream, even inside a URL or a `[host]:port`
- **Before trusting `010.1.1.1`** — which is two different hosts depending on who reads it

**Text it cannot read unambiguously is reported with the reason, never guessed at.** **It resolves nothing, looks nothing up and rewrites nothing.**

## Install

| Where | What you get | Install |
|---|---|---|
| **VS Code** | The extraction, in your editor, on a keystroke | [Marketplace](https://marketplace.visualstudio.com/items?itemName=nolindnaidoo.ips-le) |
| **Cursor, VSCodium, Windsurf** | The same extension | [Open VSX](https://open-vsx.org/extension/nolindnaidoo/ips-le) |
| **A terminal or a CI step** | A whole tree, with an exit code | `cargo install ips-le` · [crates.io](https://crates.io/crates/ips-le) |
| **Any MCP agent, via Node** | `extract_ips` over stdio | `npx ips-le-mcp` · [npm](https://www.npmjs.com/package/ips-le-mcp) |
| **Zed** | The MCP server as a context server | [add it by hand](https://zed.dev/docs/ai/mcp) *(no listing yet)* |

## What it answers

**One address, one form.** IPv6 is normalized per
[RFC 5952](https://www.rfc-editor.org/rfc/rfc5952) —
`2001:0db8:0000:0000:0000:0000:0000:0001`, `2001:db8:0:0:0:0:0:1`,
`2001:0db8::0001` and `2001:DB8::1` all come back as `2001:db8::1`.
Sorting the raw text gives four addresses; sorting the normalized form
gives one.

**Four kinds.** `ipv4`, `ipv6`, `cidr`, `mac`.

**Ten classes**, closed. A class this cannot name is a class it does not
claim.

| class | IPv4 | IPv6 |
|---|---|---|
| `loopback` | 127.0.0.0/8 | ::1 |
| `private` | 10/8, 172.16/12, 192.168/16 | — |
| `link-local` | 169.254/16 | fe80::/10 |
| `cgnat` | 100.64/10 | — |
| `multicast` | 224/4 | ff00::/8 |
| `broadcast` | 255.255.255.255 | — (IPv6 has none) |
| `documentation` | 192.0.2/24, 198.51.100/24, 203.0.113/24 | 2001:db8::/32 |
| `unique-local` | — | fc00::/7 |
| `reserved` | 0/8, 192.0.0/24, 198.18/15, 240/4 | ::, 2001::/23, 100::/64 |
| `global` | everything else | everything else |

An IPv4-mapped IPv6 address takes the IPv4 class, so `::ffff:127.0.0.1`
is `loopback` rather than `global` — which is the miss an allow-list
review is looking for.

**Where it is.** Line, column, and the key it sits under: JSON, YAML,
TOML, INI, dotenv, CSV and logs all supply one. Everything else is still
scanned — the search runs over the bytes, so a `.tf`, a `.rules` or a
rotated `access.log.1` yields its addresses and only loses the key path.

**Blocks, with their arithmetic.** A CIDR finding carries `prefix`,
`network`, `broadcast` (IPv4 only — IPv6 has none), `last` and `hosts`.
`hosts` is a decimal string, because `::/0` holds 2^128 addresses, which
is one more than a `u128` and far more than a JSON number.

```json
{
  "kind": "cidr",
  "text": "10.0.0.0/8",
  "normalized": "10.0.0.0/8",
  "class": "private",
  "cidr": {
    "prefix": 8,
    "network": "10.0.0.0",
    "broadcast": "10.255.255.255",
    "last": "10.255.255.255",
    "hosts": "16777216"
  }
}
```

## What it refuses

Where the text supports more than one reading, `ips-le` reports the
text, names the ambiguity, and stops.

Six reasons, each a place where two answers are equally defensible:

| reason | fires on |
|---|---|
| `octal_hazard` | `010.1.1.1`, `0177.0.0.1`, `192.168.001.1` |
| `ambiguous_version` | `10.0.1`, `1.2.3` — unless the key says version |
| `integer_form` | `2130706433` under an address key |
| `malformed_address` | `256.1.1.1`, `2001:db8:::1`, `12345::1` |
| `prefix_out_of_range` | `10.0.0.0/33`, `2001:db8::/129` |
| `mac_ambiguous` | `deadbeefcafe` |

The two that matter most:

- **`010.1.1.1` is not resolved.** A leading-zero octet is octal to some
  resolvers and decimal to others, so that text names two different
  hosts. Neither reading appears anywhere in the output — a tool that
  picked one would be the thing hiding the bug.
- **`2130706433` is decoded only next to the flag.** Under an address
  key it is reported as `integer_form`, with `127.0.0.1` inside the
  refusal message. What you never get is a loopback address quietly
  appearing in a list of addresses with the flag gone.

**A refusal is a finding, not a failure.** It does not move the exit
code, and no filter can hide it — filtering to `private` still shows you the
octal hazard, because that is the finding a filtered report would most
regret dropping. `--strict` is there for the pipeline that wants an
unresolved ambiguity to stop the build.

[`crate/SPEC.md`](crate/SPEC.md) says exactly when each reason fires.

## It never touches a network

No DNS, no geolocation, no ASN, no WHOIS, no reachability check, no
telemetry. Not behind a flag, not once. Classification is arithmetic
over the bits and the IANA registries; a lookup would make the answer
depend on the network the auditor happened to be sitting on.

It also never rewrites a file, and it never gives a verdict. It says
what an address *is*, never whether it should be there.

## Use it from an AI agent

The same engine runs as an [MCP](https://modelcontextprotocol.io) server, so an agent can call it directly instead of deciding by eye whether two spellings are one address.

| Editor | How |
|---|---|
| **VS Code** 1.101+ | Nothing to install — the extension registers `extract_ips` with agent mode |
| **Zed** | No listing yet — [add the MCP server by hand](https://zed.dev/docs/ai/mcp) |
| **Claude Code** | `claude mcp add ips-le -- npx -y ips-le-mcp` |
| **Cursor, Windsurf, anything else** | point it at `npx ips-le-mcp` |

```
extract_ips(content, format?, filename?, kind?, class?, maxResults?)
```

It returns the findings the editor renders, refusals included, as data — capped at 500 by default with `meta.truncated`. It reads no files and makes no network requests. Published as [`ips-le-mcp`](https://www.npmjs.com/package/ips-le-mcp) on npm and as `io.github.nolindnaidoo/ips-le` in the [MCP registry](https://registry.modelcontextprotocol.io). It answers exactly as the Rust CLI's server does: one corpus runs against both, and a differential test feeds both thousands of generated documents in every format — broken JSON included, where both report the parser's own words and position — and compares every answer.

<details>
<summary><b>Configuring it by hand</b> — any host with an MCP config file</summary>

```json
{
  "mcpServers": {
    "ips-le": {
      "command": "npx",
      "args": ["-y", "ips-le-mcp"]
    }
  }
}
```

Or install it once with `npm install -g ips-le-mcp` and point at `ips-le-mcp`. It needs no environment variables, no API key and no configuration of its own. To check it:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | npx -y ips-le-mcp
```

</details>

## The CLI

The same extraction runs over a whole tree from a terminal or a CI step: a Rust CLI in [`crate/`](crate/README.md), sharing one corpus with the extension — [`crate/fixtures/`](crate/fixtures/) — so the two can never read an address differently.

<p align="center">
  <img src="assets/demo.gif" alt="ips-le in a terminal" style="max-width: 100%; height: auto;" />
</p>

```bash
ips-le .                                   # every address in the tree, one JSON line per file
ips-le --class private --class loopback .  # what should not be reachable
ips-le --kind cidr infra/                  # every block, with its arithmetic
ips-le --strict config/                    # exit 2 on any ambiguity
ips-le mcp                                 # extract_ips and ips_le_scan over MCP on stdio
```

**Exit codes follow grep** — 0 at least one address named, 1 none, 2 the question was malformed. A refusal does not move the exit code; `--strict` is how a pipeline turns one into a failure.

## Commands

| Command | Description |
|---|---|
| `IPs-LE: Extract Addresses` (`Ctrl+Alt+A` / `Cmd+Alt+A`) | Extract every address in the active document |
| `IPs-LE: Open Settings` | Open IPs-LE settings |
| `IPs-LE: Help & Troubleshooting` | Built-in documentation |

## Settings

| Setting | Default | Description |
|---|---|---|
| `ips-le.kinds` | `[]` | Report only these kinds; empty reports every kind. Refusals are always reported |
| `ips-le.classes` | `[]` | Report only these classes; empty reports every class. Refusals are always reported |
| `ips-le.openResultsSideBySide` | `true` | Open the report beside the current editor |
| `ips-le.copyToClipboardEnabled` | `false` | Also copy the report to the clipboard |
| `ips-le.safety.enabled` | `true` | Warn before extracting from a large file |
| `ips-le.safety.fileSizeWarnBytes` | `1000000` | The size that warning starts at |
| `ips-le.notificationsLevel` | `silent` | `all` = every notification, `important` = warnings + errors, `silent` = errors only |
| `ips-le.statusBar.enabled` | `true` | Show the status bar item |
| `ips-le.telemetryEnabled` | `false` | Local-only event log (see Privacy) |

## Languages

Twelve languages besides English:

German · Spanish · French · Indonesian · Italian · Japanese · Korean ·
Portuguese (Brazil) · Russian · Ukrainian · Vietnamese · Chinese (Simplified)

Both halves are covered — the manifest (command titles, setting names and descriptions) and everything shown while the extension runs (notifications, the status bar and the report's headings). A refusal's detail is the engine's English, identical to the CLI's.

## Privacy & security

- **No network access.** The extension never sends data anywhere: no DNS, no geolocation, no lookups of any kind. The `telemetryEnabled` setting only writes events to a local Output Channel you can inspect (`IPs-LE`).
- **The MCP server holds the same line.** It takes content as an argument and returns data: no filesystem access, no network calls, no telemetry.
- Error notifications redact home directories and credential-shaped fragments.

## Documentation

| What | Where |
|---|---|
| What the tool is allowed to say — kinds, classes, refusals, the output contract, non-goals | [`crate/SPEC.md`](crate/SPEC.md) |
| How the extension is built and held together — architecture, invariants, toolchain, release | [AGENTS.md](AGENTS.md) |
| How the CLI is built and held together | [`crate/AGENTS.md`](crate/AGENTS.md) |
| What changed | [CHANGELOG.md](CHANGELOG.md) · [`crate/CHANGELOG.md`](crate/CHANGELOG.md) |
| The tool's page, and the other fifteen | [letools.dev/tools/ips-le](https://letools.dev/tools/ips-le) |

## Performance

<!-- performance:start -->
| Input | Size | Found | Time | Rate | Scan speed |
| --- | --- | --- | --- | --- | --- |
| Access log | 3.42 MB | 80,000 | 155.25 ms | 515,312/sec | 22 MB/s |
| JSON config | 2.34 MB | 60,000 | 100.48 ms | 597,123/sec | 23.3 MB/s |
| Prose with no addresses | 2.51 MB | 40,000 | 70.2 ms | 569,780/sec | 35.7 MB/s |

Median of 7 runs after warmup, on Apple M5 Pro, 24 GB RAM, Node 24.3.0. Inputs are generated
by `scripts/benchmark.ts` rather than checked in, so the sizes above are
exactly what was measured. Reproduce with `bun run benchmark`.

These are machine-specific and are not asserted in CI — a benchmark that gates
a build only tells you how busy the runner was.
<!-- performance:end -->

## Testing

<!-- coverage:start -->
| Metric | Coverage |
| --- | --- |
| Statements | 82.75% |
| Branches | 76.65% |
| Functions | 90.68% |
| Lines | 84.07% |

103 test cases across 11 files, plus an integration suite that runs
in a real VS Code extension host and an end-to-end test that installs the
built `.vsix` into a clean profile.

Generated from a real run — `coverage/coverage-summary.json` and
`coverage/test-results.json` — by `scripts/coverage-readme.js`; CI fails if
this section drifts. Reproduce with `bun run test:coverage`, and the case
count is the one vitest prints.
<!-- coverage:end -->

## More from the LE family

Sixteen single-purpose tools for the work in front of every model. Each ships
a Rust CLI and an MCP server. One page: **[letools.dev](https://letools.dev)**

**Get it out**

- **[String-LE](https://letools.dev/tools/string-le)** — Extract every string in a codebase, with its position, so a person can read them
- **[Numbers-LE](https://letools.dev/tools/numbers-le)** — Extract every hardcoded number in a codebase, so a person can check them
- **[Units-LE](https://letools.dev/tools/units-le)** — Extract every quantity with its unit, normalized, and refuse the ambiguous ones by name
- **[Dates-LE](https://letools.dev/tools/dates-le)** — Extract every date and timestamp, and the exact instant each one resolves to
- **[IDs-LE](https://letools.dev/tools/ids-le)** — Extract every UUID, ULID, NanoID, ObjectId and Snowflake, and decode the time inside
- **[IPs-LE](https://letools.dev/tools/ips-le)** — Extract every IP address, CIDR block and MAC, normalized and classified by scope
- **[URLs-LE](https://letools.dev/tools/urls-le)** — Extract every URL in a codebase, with its protocol and exact position
- **[Paths-LE](https://letools.dev/tools/paths-le)** — Extract every file path in a codebase, and say whether it still points at anything
- **[Colors-LE](https://letools.dev/tools/colors-le)** — Extract every color in a codebase, and say which ones are not in your palette

**Check it**

- **[Regex-LE](https://letools.dev/tools/regex-le)** — Find every regex in a codebase, and report which can be driven into catastrophic backtracking
- **[Versions-LE](https://letools.dev/tools/versions-le)** — Find where one dependency is constrained differently across a repository's manifests
- **[i18n-LE](https://letools.dev/tools/i18n-le)** — Identify the i18n library a project uses, then audit its catalogs by that library's rules
- **[Scrape-LE](https://letools.dev/tools/scrape-le)** — Check whether a page is scrapeable before the scraper is written, and say when it cannot tell

**Guard it**

- **[Secrets-LE](https://letools.dev/tools/secrets-le)** — Find hardcoded credentials in a codebase, and never print one into the report
- **[EnvSync-LE](https://letools.dev/tools/envsync-le)** — Compare the dotenv files in a tree, and say which keys are missing from which
- **[Unicode-LE](https://letools.dev/tools/unicode-le)** — Find the Unicode that hides meaning — bidi controls, invisibles, homoglyphs, mixed scripts

Each stands on its own: no shared crate, no published core. Where two of them
agree, it is because the same answer was right twice.

**Contact** — [nolindnaidoo.com](https://nolindnaidoo.com) · [GitHub](https://github.com/nolindnaidoo) · [LinkedIn](https://www.linkedin.com/in/nolindnaidoo/)

## Also by nolindnaidoo

**Rust** — pixelcoords and pixelactions are one loop: pixelcoords answers
*where*, pixelactions *acts* there. Their own tools, their own voice — not
part of the LE family.

- **[pixelcoords](https://github.com/nolindnaidoo/pixelcoords)** — Freeze your screen, mark regions, get pixel-exact coordinates and crops
  [pixelcoords.dev](https://pixelcoords.dev) · [crates.io](https://crates.io/crates/pixelcoords) · [docs.rs](https://docs.rs/pixelcoords)
- **[pixelactions](https://github.com/nolindnaidoo/pixelactions)** — Consume human-verified coordinates, perform the interaction, confirm it landed
  [pixelactions.dev](https://pixelactions.dev) · [crates.io](https://crates.io/crates/pixelactions) · [docs.rs](https://docs.rs/pixelactions)

## License

MIT © [nolindnaidoo](https://github.com/nolindnaidoo)
