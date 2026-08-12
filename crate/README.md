<h1 align="center">ips-le</h1>

<p align="center">
  <b>Find every IP address, CIDR block and MAC address in a tree, normalized and classified</b><br/>
  <i>and named refusals where the text has more than one reading — never a guess</i>
</p>

<p align="center">
  <a href="https://crates.io/crates/ips-le">
    <img src="https://img.shields.io/crates/v/ips-le.svg" alt="ips-le on crates.io" />
  </a>
  <img src="https://img.shields.io/badge/rustc-1.88+-93450a.svg" alt="MSRV: Rust 1.88+" />
  <a href="https://github.com/nolindnaidoo/ips-le/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT" />
  </a>
  <a href="https://letools.dev/tools/ips-le">
    <img src="https://img.shields.io/badge/web-letools.dev-00A0FF.svg" alt="letools.dev" />
  </a>
</p>

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
[SPEC.md](SPEC.md) says exactly when each fires.

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

```bash
cargo install ips-le
```

## Verifying it

The corpus ships with the crate, so the claims above are checkable
rather than trusted:

```bash
cargo test          # the RFC 5952 cases, one address per class,
                    # and every ambiguity, each expecting its refusal
```

## Documentation

- [SPEC.md](SPEC.md) — the refusal table, the classification table, the
  output schema, the non-goals.
- [CHANGELOG.md](CHANGELOG.md) — what changed and when.
- [AGENTS.md](https://github.com/nolindnaidoo/ips-le/blob/main/crate/AGENTS.md)
  — how the code is written and reviewed. Linked to the repository
  rather than relatively: it is deliberately excluded from the published
  package, so a relative link would be broken for anyone reading this on
  crates.io or from an unpacked tarball.

MIT licensed.
