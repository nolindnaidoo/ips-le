# ips-le

Find every IP address, CIDR block and MAC address in a codebase, normalize
it, and say what it is: loopback, private, link-local, cgnat, multicast,
broadcast, reserved, documentation, unique-local or global.

```bash
npx ips-le .
npx ips-le --class global infra/ > addresses.jsonl
git diff | npx ips-le --stdin
```

The command it installs is `ips-le`, the same command line as the Rust
crate [`ips-le`](https://crates.io/crates/ips-le), and it behaves
identically: same flags, same walk, same answers, same output, same exit
codes. Install whichever toolchain you already have.

## What it reports

IPv6 is normalized per RFC 5952: `2001:0db8::0001` and `2001:db8::1` are one
address, and a dedupe over the raw text reports two. JSON, YAML, TOML, INI,
dotenv, CSV and log files also give each address the key it sits under.
Every other file is still scanned, and only loses the key path.

**It refuses rather than guesses.** An address it cannot read
unambiguously is reported by name: a leading zero that some resolvers read
as octal, a dotted triple that may be a version, a bare integer in an
address field, a prefix out of range. A refusal survives `--kind` and
`--class`, because it is the finding a filtered report would hide.

It never resolves a name, never geolocates and never opens a socket.

Directories are walked the way ripgrep walks them: `.gitignore`, `.ignore`
and hidden files are respected unless you pass `--no-ignore` or `--hidden`.
A binary file, a NUL byte in its first 8 KiB, is counted and skipped. A
directory it cannot enter is reported and the walk carries on.

## Output

stdout carries one JSON report per file whenever it is piped or redirected,
and nothing when it is a terminal. stderr lists every address.

```text
$ ips-le config.json
config.json:3:17  10.0.0.5  10.0.0.5  private
config.json:4:17  2001:0db8::0001  2001:db8::1  documentation
config.json:6:16  010.1.1.1  refused OctalHazard — 010.1.1.1 has a leading zero. Some resolvers read a leading-zero octet as octal and some as decimal, so this text has two addresses and no way to choose.
3 addresses in 1 file
1 refused
```

## Exit codes

They follow grep:

- **0**: addresses found.
- **1**: none found.
- **2**: the question was malformed, or `--strict` and something was
  refused or could not be read.

## For agents

`ips-le mcp` serves the Model Context Protocol on stdio with two tools:
`extract_ips` for a document's text and `ips_le_scan` for files and
directories. Hosts that want the document tool alone can install
[`ips-le-mcp`](https://www.npmjs.com/package/ips-le-mcp).

`ips-le --help` lists every option.

MIT licensed. Part of [letools](https://letools.dev/tools/ips-le).
