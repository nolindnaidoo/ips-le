<h1 align="center">IPs-LE</h1>

<p align="center">
  <b>Find every IP address, CIDR block and MAC address in a tree, normalized and classified</b><br/>
  <i>and named refusals where the text has more than one reading — never a guess</i>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/rustc-1.88+-93450a.svg" alt="MSRV: Rust 1.88+" />
  <a href="https://github.com/nolindnaidoo/ips-le/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT" />
  </a>
  <a href="https://letools.dev/tools/ips-le">
    <img src="https://img.shields.io/badge/LE%20Tools-letools.dev-blue.svg" alt="LE Tools" />
  </a>
</p>

---

Somebody has to check the firewall allow-list against the change
request, the connection string against the network diagram, the fetch
path against the SSRF review. Usually without a checkout, always without
the editor open.

`grep -rE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'` half-serves them. It finds
no IPv6 at all. It calls `1.2.3` an address. It reports
`2001:0db8::0001` and `2001:db8::1` as two different things — they are
one address. And it calls `010.1.1.1` an address without saying *which*
address, which is the whole reason that string is an SSRF bypass.

```bash
ips-le .
```

## What it does

Walks a tree the way ripgrep does, reads the bytes of every text file in
it, and reports every network address it finds: as written, normalized,
classified, with its line, column and — where the format has one — the
key it sits under. stdout is one JSON report per line; stderr is the
same answer for a person.

```
$ ips-le crate/fixtures/documents/network.yaml
crate/fixtures/documents/network.yaml:3:11  0.0.0.0  0.0.0.0  reserved
crate/fixtures/documents/network.yaml:4:15  10.20.30.40  10.20.30.40  private
crate/fixtures/documents/network.yaml:6:11  127.0.0.1  127.0.0.1  loopback
crate/fixtures/documents/network.yaml:7:11  2001:0db8::0001  2001:db8::1  documentation
crate/fixtures/documents/network.yaml:9:5  10.0.0.0/8  10.0.0.0/8  private
crate/fixtures/documents/network.yaml:10:5  192.168.0.0/16  192.168.0.0/16  private
crate/fixtures/documents/network.yaml:11:11  169.254.169.254  169.254.169.254  link-local
crate/fixtures/documents/network.yaml:12:11  aa:bb:cc:dd:ee:ff  aa:bb:cc:dd:ee:ff  global
8 addresses in 1 file
```

## Sixty seconds

```bash
ips-le .                                   # every address in the tree, as JSON
ips-le --class private --class loopback .  # what should not be reachable
ips-le --kind cidr infra/                  # every block, with its arithmetic
ips-le --strict config/                    # fail the build on any ambiguity
cat access.log | ips-le --stdin --format log

# the point of the whole thing:
ips-le . | jq -r '.addresses[] | select(.normalized) | .normalized' | sort -u
```

Every line of stdout is one file's report, and every field is always
present — nulls included — so a consumer writes one reader:

```json
{
  "schema": 1,
  "file": "<stdin>",
  "format": "yaml",
  "addresses": [
    {
      "kind": "ipv6",
      "text": "2001:0db8::0001",
      "line": 3,
      "column": 11,
      "key": "services.cache.peer",
      "normalized": "2001:db8::1",
      "class": "documentation",
      "cidr": null,
      "refused": null
    }
  ],
  "diagnostics": [],
  "summary": { "addresses": 1, "refused": 0 }
}
```

There is no `--json` flag. One mode, nothing to misremember, and the
human summary is a projection of the machine one so the two cannot
drift.

## What it answers

**One address, one form.** IPv6 is normalized per
[RFC 5952](https://www.rfc-editor.org/rfc/rfc5952) —
`2001:0db8:0000:0000:0000:0000:0000:0001`, `2001:db8:0:0:0:0:0:1`,
`2001:0db8::0001` and `2001:DB8::1` all come back as `2001:db8::1`.
Sorting the raw text gives four addresses; sorting the normalized form
gives one.

**Four kinds.** `ipv4`, `ipv6`, `cidr`, `mac` — and `--kind` takes the
same four names.

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

```
$ ips-le --stdin <<< '010.1.1.1'
<stdin>:1:1  010.1.1.1  refused OctalHazard
0 addresses in 1 file
1 refused
```

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
code, and no filter can hide it — `--class private` still shows you the
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

## Exit codes

Following grep:

| code | meaning |
|---|---|
| `0` | at least one address was named |
| `1` | none was |
| `2` | the question was malformed |

Finding none is an answer, and so is a refusal — a file of nothing but
ambiguities exits 1. `--strict` turns a refusal, or a file that could
not be read, into a 2. A binary file is counted and never fails the run;
every repository holds a PNG.

```bash
if ips-le --strict --class loopback config/; then
  echo "a loopback address is hardcoded in config/"
fi
```

## As an MCP server

```bash
ips-le mcp
```

Two tools, one envelope (`{ ok, data, diagnostics, meta }`):

- **`extract_ips`** — takes document text, returns findings. Touches no
  filesystem.
- **`ips_le_scan`** — takes a path, reads the tree.

`ok` means the scan ran, never that the answer was yes. A model reading
`2001:0db8::0001` and `2001:db8::1` out of a diff will usually call them
two addresses; this is how it stops having to guess.

## Install

**Not on crates.io yet.** `cargo install ips-le` does not work today —
0.1.0 is unpublished. Build it from this repository instead:

```bash
git clone https://github.com/nolindnaidoo/ips-le
cd ips-le
cargo install --path crate
```

That puts `ips-le` in `~/.cargo/bin`. Rust 1.88 or newer.

## Layout

This repository is **crate-only**: the Rust CLI and MCP server, and
nothing else.

```
crate/
├── src/
│   ├── extract/    pure: the scanner, the policy layer, the seven key
│   │               readers, positions. No filesystem, no network.
│   ├── walk.rs     ignore-aware tree walking
│   ├── scan.rs     one file end to end — the only path either surface calls
│   ├── cli.rs      the terminal surface
│   └── mcp/        the agent surface
├── fixtures/       the corpus, embedded and run by `cargo test`
└── tests/          contracts · scenarios · hazards · platform · fuzz ·
                    budget · coverage_matrix
```

## Development

```bash
cd crate
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
```

Those three are the definition of done and are exactly what CI runs.
Four more suites are gated so a bare `cargo test` stays fast, and CI
turns each of them on:

| suite | what it is for | how to run it |
|---|---|---|
| `hazards` | a byte-order mark, a UTF-16 log, a FIFO, a symlink loop, a locked directory, a path over 260 characters | `cargo test --test hazards` |
| `platform` | one path separator on every OS, case folding, reserved Windows names, CRLF, stdin, `TZ` | `cargo test --test platform` |
| `fuzz` | generated input against the scanner's three splitting rules | `IPS_LE_FUZZ_SECONDS=60 cargo test --test fuzz` |
| `budget` | a wall-clock ceiling and three linearity checks | `IPS_LE_BUDGET=1 cargo test --test budget` |
| `coverage_matrix` | every kind, class, refusal reason and format reachable from a real fixture | `cargo test --test coverage_matrix -- --nocapture` |
| `scenarios` | documents larger than an editor opens | `IPS_LE_SCENARIOS=1 cargo test --test scenarios` |

The corpus ships inside the crate, so `cargo test` on an unpacked
tarball runs every RFC 5952 case, one address per class, and every
ambiguity expecting its refusal — the claims above are checkable rather
than trusted.

## Documentation

- [`crate/SPEC.md`](crate/SPEC.md) — the refusal table, the
  classification table, the output schema, the non-goals.
- [`crate/AGENTS.md`](crate/AGENTS.md) — how the code is written and
  reviewed.
- [`crate/README.md`](crate/README.md) — the crate's own front page.
- [`CHANGELOG.md`](CHANGELOG.md) — what changed and when.

## More from the LE Family

Every tool in the family, one page: **[letools.dev](https://letools.dev)**

- **[Paths-LE](https://letools.dev/tools/paths-le)** — Extract file paths from JS/TS imports, JSON, HTML, CSS, TOML, CSV, and .env
- **[String-LE](https://letools.dev/tools/string-le)** — Extract string values for i18n from JSON, YAML, CSV, TOML, INI, and .env
- **[Numbers-LE](https://letools.dev/tools/numbers-le)** — Extract numeric values from JSON, YAML, CSV, TOML, INI, and .env
- **[EnvSync-LE](https://letools.dev/tools/envsync-le)** — Spot missing keys across your .env files, with a markdown report
- **[Regex-LE](https://letools.dev/tools/regex-le)** — Find, test, and validate regular expressions with ReDoS screening
- **[Secrets-LE](https://letools.dev/tools/secrets-le)** — Detect and sanitize credentials locally, before you commit
- **[Colors-LE](https://letools.dev/tools/colors-le)** — Extract and analyze colors from CSS, SCSS, LESS, Stylus, HTML, JS/TS, and SVG
- **[URLs-LE](https://letools.dev/tools/urls-le)** — Extract URLs from documentation, configs, and code
- **[Dates-LE](https://letools.dev/tools/dates-le)** — Extract and analyze dates from logs, configs, and code
- **[Scrape-LE](https://letools.dev/tools/scrape-le)** — Load a URL in headless Chromium and see what will block your scraper

**Contact Developer** — [nolindnaidoo.com](https://nolindnaidoo.com) · [GitHub](https://github.com/nolindnaidoo) · [LinkedIn](https://www.linkedin.com/in/nolindnaidoo/)

## License

MIT © [nolindnaidoo](https://github.com/nolindnaidoo)
