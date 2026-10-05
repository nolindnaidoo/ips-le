# ips-le-mcp

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
  <a href="https://letools.dev/tools/ips-le">
    <img src="https://img.shields.io/badge/LE%20Tools-letools.dev-blue?style=for-the-badge" alt="LE Tools" />
  </a>
</p>

An [MCP](https://modelcontextprotocol.io) server that finds every IPv4 and
IPv6 address, CIDR block and MAC address in a document — with its line,
column and key path, its canonical form, and what it is for: loopback,
private, link-local, CGNAT, multicast, broadcast, reserved, documentation,
unique-local or global. It is the extraction engine behind the
[IPs-LE](https://letools.dev/tools/ips-le) editor extension, exposed as a tool
an agent can call.

**IPv6 comes back in its RFC 5952 form**, so `2001:0db8::0001` and
`2001:db8::1` are one address rather than two, and `::ffff:127.0.0.1` is
classified as the loopback address it is.

**Text it cannot read unambiguously comes back as a refusal with the reason,
never as a guess.** `010.1.1.1` is 8.1.1.1 to a resolver that reads the
leading zero as octal and 10.1.1.1 to one that does not, so it is returned as
`octal_hazard` rather than as either address.

No dependencies, no network calls, no filesystem access. It resolves no names
and opens no sockets. Content goes in, structured results come out.

## Use it

Point any MCP host at `npx ips-le-mcp`.

**Claude Code**

```bash
claude mcp add ips-le -- npx -y ips-le-mcp
```

**Anything with a JSON config** — Cursor, Windsurf, Claude Desktop:

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

**VS Code** needs nothing here. Install the extension instead — it
carries this server and registers it for you:
[VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=nolindnaidoo.ips-le)
· [Open VSX](https://open-vsx.org/extension/nolindnaidoo/ips-le)

**No Node?** The same `extract_ips` tool ships in a static Rust binary:
`cargo install ips-le`, then `ips-le mcp`
([crates.io](https://crates.io/crates/ips-le)). The two servers answer
identically — one corpus runs against both, and a differential test feeds both
thousands of generated documents in every format, broken JSON included, and
compares every answer. The binary additionally offers `ips_le_scan`, which
walks a tree; **this server reads no files**.

Prefer a global install to `npx` on every launch:

```bash
npm install -g ips-le-mcp
```

No environment variables, no API key, no configuration of its own. To check it
before wiring it into anything:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | npx -y ips-le-mcp
```

If that prints the tool name, the server works.

## The tool

### `extract_ips`

| argument | type | |
|---|---|---|
| `content` | string | **required.** The document text to scan. |
| `format` | string | `json`, `yaml`, `toml`, `ini`, `env`, `csv`, `tsv` or `log`. Optional — it decides only the key paths, never which addresses are found. |
| `filename` | string | Used to infer the format when `format` is absent, e.g. `app.yaml` or `access.log.1`. |
| `kind` | string[] | Report only these of `ipv4`, `ipv6`, `cidr`, `mac`. Refusals are always reported. |
| `class` | string[] | Report only these classes. Refusals are always reported. |
| `maxResults` | number | Default `500`, ceiling `5000`. |

Every finding carries every field, nulls included: the text as written, a
1-based line and UTF-16 column, the key, the canonical form, the class, a CIDR
block's network, last address and host count (as a decimal string — `::/0`
holds 2^128), and the refusal:

```json
{
  "ok": true,
  "data": {
    "addresses": [
      {
        "kind": "ipv6",
        "text": "2001:0db8:0000:0000:0000:0000:0000:0001",
        "line": 1,
        "column": 11,
        "key": "upstream",
        "normalized": "2001:db8::1",
        "class": "documentation",
        "cidr": null,
        "refused": null
      },
      {
        "kind": "cidr",
        "text": "10.0.0.0/30",
        "line": 2,
        "column": 8,
        "key": "allow",
        "normalized": "10.0.0.0/30",
        "class": "private",
        "cidr": {
          "prefix": 30,
          "network": "10.0.0.0",
          "broadcast": "10.0.0.3",
          "last": "10.0.0.3",
          "hosts": "4"
        },
        "refused": null
      },
      {
        "kind": "ipv4",
        "text": "010.1.1.1",
        "line": 3,
        "column": 9,
        "key": "legacy",
        "normalized": null,
        "class": null,
        "cidr": null,
        "refused": {
          "reason": "octal_hazard",
          "detail": "010.1.1.1 has a leading zero. Some resolvers read a leading-zero octet as octal and some as decimal, so this text has two addresses and no way to choose."
        }
      }
    ],
    "refused": 1,
    "format": "yaml"
  },
  "diagnostics": [],
  "meta": {
    "tool": "extract_ips",
    "count": 3,
    "truncated": false
  }
}
```

A JSON document that does not parse still has its addresses reported, with an
`unparsed` warning saying the key paths are missing. `ok` means the scan ran.

## Also in the MCP registry

`io.github.nolindnaidoo/ips-le` —
[registry.modelcontextprotocol.io](https://registry.modelcontextprotocol.io)

## Thirteen more like it

One tool each, same shape: content in, structured data out, no network and no
filesystem. Every one is on npm as `<name>-mcp` and in the MCP registry as
`io.github.nolindnaidoo/<name>`.

| Package | Tool | Does |
|---|---|---|
| [`urls-le-mcp`](https://www.npmjs.com/package/urls-le-mcp) | `extract_urls` | URLs, with protocol and position |
| [`colors-le-mcp`](https://www.npmjs.com/package/colors-le-mcp) | `extract_colors` | colors from stylesheets and code |
| [`dates-le-mcp`](https://www.npmjs.com/package/dates-le-mcp) | `extract_dates` | dates and timestamps |
| [`numbers-le-mcp`](https://www.npmjs.com/package/numbers-le-mcp) | `extract_numbers` | numeric values |
| [`paths-le-mcp`](https://www.npmjs.com/package/paths-le-mcp) | `extract_paths` | file and directory paths |
| [`string-le-mcp`](https://www.npmjs.com/package/string-le-mcp) | `extract_strings` | string values |
| [`regex-le-mcp`](https://www.npmjs.com/package/regex-le-mcp) | `extract_patterns` | regexes, with a ReDoS verdict |
| [`secrets-le-mcp`](https://www.npmjs.com/package/secrets-le-mcp) | `detect_secrets` | credentials, masked — never the value |
| [`envsync-le-mcp`](https://www.npmjs.com/package/envsync-le-mcp) | `compare_env_files` | dotenv key drift, names only |
| [`scrape-le-mcp`](https://www.npmjs.com/package/scrape-le-mcp) | `analyze_robots_txt` | whether a path may be crawled |
| [`unicode-le-mcp`](https://www.npmjs.com/package/unicode-le-mcp) | `detect_unicode_risks` | Unicode that hides meaning, as codepoints |
| [`i18n-le-mcp`](https://www.npmjs.com/package/i18n-le-mcp) | `check_catalogues` | translation catalogues, keys only |
| [`ids-le-mcp`](https://www.npmjs.com/package/ids-le-mcp) | `extract_ids` | UUIDs, ULIDs and Snowflakes, with the time inside |

Every tool in the family, one page: **[letools.dev](https://letools.dev)**

## Built by

**[Nolin Naidoo](https://nolindnaidoo.com)** — Chief Engineer, AI/ML & Platform
Architecture. [nolindnaidoo.com](https://nolindnaidoo.com) ·
[GitHub](https://github.com/nolindnaidoo) ·
[LinkedIn](https://www.linkedin.com/in/nolindnaidoo/)

### Also from the same workshop

Twelve Rust tools built the same way: small, single-purpose, and driven by a
machine rather than a person. pixelcoords and pixelactions make up one loop —
pixelcoords answers *where*, pixelactions *acts* there. The ten LE crates are
the terminal half of the extensions they sit in: the same detection, held to
the extension's own corpus, and an exit code instead of a results editor.

| | | |
|---|---|---|
| **[pixelcoords](https://github.com/nolindnaidoo/pixelcoords)** | Freeze your screen, mark regions, get pixel-exact coordinates and crops | [site](https://pixelcoords.dev) · [crates.io](https://crates.io/crates/pixelcoords) · [docs.rs](https://docs.rs/pixelcoords) |
| **[pixelactions](https://github.com/nolindnaidoo/pixelactions)** | Consume human-verified coordinates, perform the interaction, confirm it landed | [site](https://pixelactions.dev) · [crates.io](https://crates.io/crates/pixelactions) · [docs.rs](https://docs.rs/pixelactions) |
| **[paths-le](https://github.com/nolindnaidoo/paths-le/tree/main/crate)** | Find every path in a codebase and report whether it still points at anything | [crates.io](https://crates.io/crates/paths-le) |
| **[secrets-le](https://github.com/nolindnaidoo/secrets-le/tree/main/crate)** | Find hardcoded credentials, and never print one | [crates.io](https://crates.io/crates/secrets-le) |
| **[urls-le](https://github.com/nolindnaidoo/urls-le/tree/main/crate)** | Extract every URL from a codebase, with its protocol and exact position | [crates.io](https://crates.io/crates/urls-le) |
| **[regex-le](https://github.com/nolindnaidoo/regex-le/tree/main/crate)** | Find every regex in a codebase and report which can be driven into catastrophic backtracking | [crates.io](https://crates.io/crates/regex-le) |
| **[string-le](https://github.com/nolindnaidoo/string-le/tree/main/crate)** | Get every string in a codebase out where a person can read them | [crates.io](https://crates.io/crates/string-le) |
| **[numbers-le](https://github.com/nolindnaidoo/numbers-le/tree/main/crate)** | Find every hardcoded number in a codebase so a person can check them | [crates.io](https://crates.io/crates/numbers-le) |
| **[envsync-le](https://github.com/nolindnaidoo/envsync-le/tree/main/crate)** | Compare the dotenv files in a tree and say which keys are missing from which | [crates.io](https://crates.io/crates/envsync-le) |
| **[colors-le](https://github.com/nolindnaidoo/colors-le/tree/main/crate)** | Find every colour in a codebase, and say which are not in your palette | [crates.io](https://crates.io/crates/colors-le) |
| **[dates-le](https://github.com/nolindnaidoo/dates-le/tree/main/crate)** | Extract every date and timestamp, and the exact instant each one resolves to | [crates.io](https://crates.io/crates/dates-le) |
| **[scrape-le](https://github.com/nolindnaidoo/scrape-le/tree/main/crate)** | Check whether a page is scrapeable before the scraper is written | [crates.io](https://crates.io/crates/scrape-le) |

## Licence

MIT © [Nolin Naidoo](https://nolindnaidoo.com)
