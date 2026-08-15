<p align="center">
  <img src="https://raw.githubusercontent.com/nolindnaidoo/ips-le/main/assets/icon.png" alt="ips-le logo" width="96" height="96"/>
</p>

<h1 align="center">ips-le</h1>

<p align="center">
  <b>Find every IP address, CIDR block and MAC address in a tree, normalized and classified</b><br/>
  <i>and named refusals where the text has more than one reading — never a guess</i>
</p>

<p align="center">
  <a href="https://crates.io/crates/ips-le">
    <img src="https://img.shields.io/crates/v/ips-le.svg" alt="ips-le on crates.io" />
  </a>
  <a href="https://crates.io/crates/ips-le">
    <img src="https://img.shields.io/crates/d/ips-le.svg" alt="crates.io downloads" />
  </a>
  <a href="https://github.com/nolindnaidoo/ips-le/actions/workflows/ci-crate.yml">
    <img src="https://github.com/nolindnaidoo/ips-le/actions/workflows/ci-crate.yml/badge.svg" alt="Build Status" />
  </a>
  <img src="https://img.shields.io/badge/rustc-1.88+-93450a.svg" alt="MSRV: Rust 1.88+" />
  <a href="https://github.com/nolindnaidoo/ips-le/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT" />
  </a>
  <a href="https://letools.dev/tools/ips-le">
    <img src="https://img.shields.io/badge/web-letools.dev-00A0FF.svg" alt="letools.dev" />
  </a>
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/nolindnaidoo/ips-le/main/assets/demo.gif" alt="ips-le demo — the real binary, recorded by assets/demo.tape" width="100%"/>
</p>

> **Useful?** A star is how other developers find it —
> [★ GitHub](https://github.com/nolindnaidoo/ips-le) ·
> [letools.dev/tools/ips-le](https://letools.dev/tools/ips-le)

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

## Install

```bash
cargo install ips-le
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

stderr, in full, for one of the fixture documents that ships with the
crate — `ips-le fixtures/documents/network.yaml`:

```
fixtures/documents/network.yaml:3:11  0.0.0.0  0.0.0.0  reserved
fixtures/documents/network.yaml:4:15  10.20.30.40  10.20.30.40  private
fixtures/documents/network.yaml:6:11  127.0.0.1  127.0.0.1  loopback
fixtures/documents/network.yaml:7:11  2001:0db8::0001  2001:db8::1  documentation
fixtures/documents/network.yaml:9:5  10.0.0.0/8  10.0.0.0/8  private
fixtures/documents/network.yaml:10:5  192.168.0.0/16  192.168.0.0/16  private
fixtures/documents/network.yaml:11:11  169.254.169.254  169.254.169.254  link-local
fixtures/documents/network.yaml:12:11  aa:bb:cc:dd:ee:ff  aa:bb:cc:dd:ee:ff  global
fixtures/documents/network.yaml:14:11  10.0.0.7  10.0.0.7  private
fixtures/documents/network.yaml:14:26  10.0.0.8  10.0.0.8  private
10 addresses in 1 file
```

The last two are one line — `fallback: 10.0.0.7 # was 10.0.0.8`. Both
addresses are reported, because an address in a comment is one a
reviewer came for; only the first carries the key `fallback`, because
the file does not bind to the other one.

## What it answers

**One address, one form.** IPv6 is normalized per
[RFC 5952](https://www.rfc-editor.org/rfc/rfc5952) —
`2001:0db8:0000:0000:0000:0000:0000:0001`, `2001:db8:0:0:0:0:0:1`,
`2001:0db8::0001` and `2001:DB8::1` all come back as `2001:db8::1`.
Sorting the raw text gives four addresses; sorting the normalized form
gives one.

**What it is for.** Every address carries a class: `loopback`,
`private`, `link-local`, `cgnat`, `multicast`, `broadcast`, `reserved`,
`documentation`, `unique-local`, `global`. An IPv4-mapped IPv6 address
takes the IPv4 class, so `::ffff:127.0.0.1` is `loopback` rather than
`global` — which is the miss an allow-list review is looking for.

**Where it is.** Line, column, and the key it sits under: JSON, YAML,
TOML, INI, dotenv, CSV and logs all supply one. Everything else is still
scanned — the search runs over the bytes, so a `.tf`, a `.rules` or a
rotated log yields its addresses and only loses the key path.

**Blocks, with their arithmetic.** A CIDR finding carries `prefix`,
`network`, `broadcast`, `last` and `hosts` — `hosts` as a decimal
string, because `::/0` holds 2^128 addresses.

## What it refuses

Where the text supports more than one reading, `ips-le` reports the
text, names the ambiguity, and stops.

```
$ ips-le --stdin <<< '010.1.1.1'
<stdin>:1:1  010.1.1.1  refused OctalHazard
0 addresses in 1 file
1 refused
```

Six reasons: `octal_hazard`, `ambiguous_version`, `integer_form`,
`malformed_address`, `prefix_out_of_range`, `mac_ambiguous`. Each one is
a place where two answers are equally defensible, and
[SPEC.md](https://github.com/nolindnaidoo/ips-le/blob/main/crate/SPEC.md) says exactly when each fires.

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

## It never touches a network

No DNS, no geolocation, no ASN, no WHOIS, no reachability check, no
telemetry. Not behind a flag, not once. Classification is arithmetic
over the bits and the IANA registries; a lookup would make the answer
depend on the network the auditor happened to be sitting on.

It also never rewrites a file, and it never gives a verdict. It says
what an address *is*, never whether it should be there.

## Exit codes

Following grep: **0** addresses found · **1** none found · **2**
malformed question. Finding none is an answer, and so is a refusal — a
file of nothing but ambiguities exits 1. `--strict` turns a refusal, or
a file that could not be read, into a 2.

```bash
if ips-le --strict --class loopback config/; then
  echo "a loopback address is hardcoded in config/"
fi
```

## Options

Taken from `ips-le --help`, which is the authority.

| Option | What it does |
|---|---|
| `--format <format>` | Force a format instead of inferring it from the file name; an unknown name still scans, it just reports no key paths |
| `--kind <kind>` | Report only `ipv4`, `ipv6`, `cidr` or `mac`; repeatable |
| `--class <class>` | Report only one class, e.g. `private` or `global`; repeatable |
| `--strict` | Exit 2 if anything was refused or any file could not be read, rather than reporting it and carrying on |
| `--stdin` | Read one document from stdin |
| `--hidden` | Walk hidden files and directories too |
| `--no-ignore` | Walk files that `.gitignore` excludes |

A filter narrows what this tool claims, never what it declined to claim:
a refusal survives `--kind` and `--class`, because the finding a filtered
report would hide is the one most worth seeing.

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

## Documentation

- [SPEC.md](https://github.com/nolindnaidoo/ips-le/blob/main/crate/SPEC.md) — the refusal table, the classification table, the
  output schema, the non-goals.
- [CHANGELOG.md](https://github.com/nolindnaidoo/ips-le/blob/main/crate/CHANGELOG.md) — what changed and when.
- [AGENTS.md](https://github.com/nolindnaidoo/ips-le/blob/main/crate/AGENTS.md)
  — how the code is written and reviewed. Linked to the repository
  rather than relatively: it is deliberately excluded from the published
  package, so a relative link would be broken for anyone reading this on
  crates.io or from an unpacked tarball.


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

MIT — see [LICENSE](https://github.com/nolindnaidoo/ips-le/blob/main/LICENSE).
