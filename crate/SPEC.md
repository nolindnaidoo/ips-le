# ips-le — specification

Find every IP address, CIDR block and MAC address in a tree, normalize
it, and say what it is — or say, by name, why it could not be said.

## The one question

**Which network addresses are hardcoded in here, and what are they?**

Asked over a whole tree rather than a buffer, and answered into
something a person or a script can act on.

## Who asks it

Someone auditing a boundary. A firewall allow-list against a change
request. A connection string against a network diagram. An SSRF review
against a fetch path. A log against "who actually talked to this
service".

`grep -rE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'` half-serves them. It finds
no IPv6 at all, calls `1.2.3` an address, calls `010.1.1.1` an address
without saying which one, and reports `2001:0db8::0001` and
`2001:db8::1` as two different things.

## The hard part: one address, many spellings

IPv6 has no single textual form. `2001:0db8:0000:0000:0000:0000:0000:0001`,
`2001:db8:0:0:0:0:0:1`, `2001:0db8::0001` and `2001:DB8::1` are one
address written four ways. A dedupe over raw text reports four. A diff
between two configs reports a change that is not one.

So **every address is reported both as written and normalized**, and the
IPv6 normalization is [RFC 5952](https://www.rfc-editor.org/rfc/rfc5952):
lowercase, no leading zeros, the longest run of zero groups compressed
to `::` (leftmost on a tie, never a single group), and a well-known
IPv4-embedded prefix keeps its dotted tail. `fixtures/extraction.json`
pins the rules that are easiest to get wrong, against the RFC's own
examples.

## Refusals — the design spine

**This tool never guesses what an address is.** Where the text supports
more than one reading, it reports the text, names the ambiguity, and
stops. A refusal is a finding, not a failure: it does not move the exit
code unless `--strict`, and no filter can hide it.

| reason | fires on | why it is not answerable |
|---|---|---|
| `octal_hazard` | `010.1.1.1`, `0177.0.0.1`, `192.168.001.1` | A leading-zero octet is octal to some resolvers and decimal to others. `010.1.1.1` is a different host depending on who reads it, which is what makes it an SSRF bypass. **Neither reading appears in the output.** |
| `ambiguous_version` | `10.0.1`, `1.2.3` | Three dotted groups: a version string, or an IPv4 address missing an octet. Suppressed entirely when the key says version (`version`, `app_version`, `ver`, `rev`) — then it is a version, not an ambiguity. |
| `integer_form` | `2130706433` under an address key | A dotted quad written as a 32-bit integer. Some resolvers accept it; this one will not decide that they did. The decoded form appears **only inside the refusal**, so the address is never available without the flag. Requires an address key (`*ip`, `*addr`, `*address`, `*host`, `*gateway`, `*cidr`, `*subnet`) — otherwise it is a number. |
| `malformed_address` | `256.1.1.1`, `1.2.3.9999`, `2001:db8:::1`, `12345::1` | The right shape, and it did not parse. |
| `prefix_out_of_range` | `10.0.0.0/33`, `2001:db8::/129` | A prefix outside 0–32 (v4) or 0–128 (v6). |
| `mac_ambiguous` | `deadbeefcafe` | Twelve hex digits with no separator and at least one letter: a bare MAC address, or the front of a hash. All-digits is a number and any other length is not a MAC, so neither reaches this. |

Every one of these has a case in `fixtures/extraction.json` under
`ambiguity`, and **every case there expects a refusal**. If one ever
comes back as an address, a guess was introduced.

## Classification

Ten values, closed. A class this cannot name is a class it does not
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

**An IPv4-mapped IPv6 address takes the IPv4 class.**
`::ffff:127.0.0.1` is `loopback` and `::ffff:169.254.169.254` is
`link-local` — calling either `global` is exactly the miss an allow-list
review is trying to find.

A **CIDR block is classified by its network address**, and reports
`prefix`, `network`, `broadcast` (IPv4 only), `last` and `hosts`.
`hosts` is a decimal string: `::/0` holds 2^128 addresses, which is one
more than a `u128` and far more than a JSON number.

A **MAC address** reports `broadcast` for `ff:ff:ff:ff:ff:ff`,
`multicast` when the I/G bit is set, and `global` otherwise. The
universal/local bit is not reported in 0.1.0 — none of the ten classes
means it.

## Shape

**One crate.** Self-contained: no published `-core`, no shared crate
with the family, and nothing holding this code equal to the similar
files in the sibling repos.

```
crate/
├── src/
│   ├── extract/    pure: the scanner, the policy layer, the seven key
│   │               readers, positions. No filesystem, no network.
│   ├── walk.rs     ignore-aware tree walking
│   ├── scan.rs     one file end to end — the only path either surface calls
│   ├── cli.rs      the terminal surface
│   └── mcp/        the agent surface
└── fixtures/       the corpus, embedded and run by `cargo test`
```

Inside `extract/`:

```
scanner.rs   bytes  → candidate runs      (format-independent)
<format>.rs  bytes  → key spans           (json yaml toml ini env csv log)
policy.rs    run    → address or refusal  (the decision layer)
locate.rs    joins the three
```

**The scan runs over the bytes of every document, whatever its format.**
That is the decision the crate is built around, and it is the opposite
of the sibling extractors. A network address is almost never a value —
it is inside one (`postgres://10.0.0.5:5432/app`), or inside a log line,
which has no values at all. The format parse contributes **only the key
path**, so an unrecognised format costs a locator and never an address.

The cost is that keys, comments and prose are scanned too, and an
address in a comment is reported with no key. That is the right trade
here: an address hardcoded in a comment is an address a reviewer came
for.

## What the scanner declines to consider

A log file is mostly timestamps, durations, ports, hashes and paths,
built from the same alphabet as an address. Three rules keep them out of
the report, and out of the refusal vocabulary:

- **A run glued to a name is part of that name.** `Ipv6Addr::from_str`
  contains `::f`, a valid IPv6 address; `v1.2.3.4` contains a valid
  IPv4 one. Both are dropped. A *single* separator between a name and a
  run is punctuation, not glue, so `client_ip:10.0.0.1` still works.
- **A colon run splits unless it is IPv6-shaped** — `::` present, seven
  colons, or six with a dotted tail. `127.0.0.1:5432` becomes the
  address and the port; `2026:10:30:00` becomes four numbers and no
  finding.
- **A hyphen run splits unless it is a MAC** — six two-digit hex groups
  under one separator. `10.0.0.1-10.0.0.9` is two addresses;
  `2026-08-12` is three numbers.

## Output

stdout is protocol: one JSON report per line, one line per file. stderr
is human, and is a projection of the same reports. **There is no
`--json` flag** — one mode, nothing to misremember, and the two cannot
drift.

```json
{
  "schema": 1,
  "file": "app.yaml",
  "format": "yaml",
  "addresses": [
    {
      "kind": "ipv6",
      "text": "2001:0db8::0001",
      "line": 7,
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

**Every field is always present, nulls included**, so a consumer writes
one reader and never has to decide whether an absent key and a null key
mean different things. `kind` is `null` where the refusal is about which
kind it is.

`summary.addresses` counts what was named; `summary.refused` counts what
was not. The `addresses` array holds both.

### Exit codes

Following grep:

| code | meaning |
|---|---|
| `0` | at least one address was named |
| `1` | none was |
| `2` | the question was malformed |

Finding nothing is an answer. **So is a refusal** — a file of nothing
but ambiguities exits 1, not 2. `--strict` turns any refusal, and any
file that could not be read, into a 2.

## Formats

`json` `yaml` `toml` `ini` `env` `csv` `log`, plus the fallback
`unknown`. The format decides **only** whether a finding carries a key
path.

- **json** — the one format with a parser (`jsonc-parser`), because a
  minified document is one line and a line-oriented key reader answers
  nothing for it. Comments and trailing commas accepted. A document
  that does not parse still gets its full byte scan; the diagnostic
  says the key paths are missing, not that nothing was found.
- **yaml** — indentation, tracked as a stack of `(column, key)`.
- **toml** — table headers, plus a key that stays open across a
  multi-line array, because an allow-list is written that way.
- **ini** — `[section]` and `key = value` / `key: value`.
- **env** — `KEY=value`, `export` stripped.
- **csv** — every row is data; the key is a coordinate, `[row][column]`.
- **log** — logfmt `key=value` pairs and JSON-per-line. An Apache or
  syslog line gets no key path, and that is the honest answer: the
  address is in position one of a format nobody declared.
- **unknown** — no key paths, every address.

A rotated log (`access.log.1`, `syslog.log.2026-08-12`) resolves to
`log`.

## Non-goals

**Never any of these, not behind a flag, not once:**

- **No DNS resolution.** A hostname is not an address, and asking a
  resolver would make the answer depend on the network the auditor
  happened to be sitting on.
- **No geolocation.** No ASN, no country, no owner. Those are database
  lookups whose answers change without the file changing.
- **No network access of any kind.** No connect, no ping, no WHOIS, no
  reachability, no telemetry. This tool reads bytes.
- **No verdict.** It says what an address *is*, never whether it should
  be there. There is no allow-list, no severity, no "this looks
  dangerous". Which addresses matter is the reader's call.
- **No rewriting.** It never edits a file.

## Known limits in 0.1.0

Written down rather than discovered:

- **Cisco dotted MAC notation** (`aabb.ccdd.eeff`) is not read.
- **IPv6 zone identifiers** are dropped before parsing; `fe80::1%eth0`
  is reported as `fe80::1` with the raw text preserved. A zone names an
  interface on one machine, not a part of the address.
- **YAML flow mappings, anchors, merge keys and block scalars** get a
  coarser key path than a real parser would give. The address is
  unaffected.
- **A TOML array of tables** flattens to one path for every element:
  `[[peers]]` gives `peers.addr`, not `peers[0].addr`.
- **A trailing `/24` after a URL path** (`http://10.0.0.1/24`) reads as
  a block. Rare, and preferred to losing every CIDR written after a
  slash.
- **`--class` and `--kind` accumulate** and are ORs within a dimension,
  ANDs across them. There is no negation.
