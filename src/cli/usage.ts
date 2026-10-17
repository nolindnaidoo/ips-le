/**
 * The command line's help text and the flags it names.
 *
 * Word for word the Rust CLI's, because both install as `ips-le` and a
 * person reading `--help` cannot tell which one they have.
 * `scripts/check-cli-parity.ts` compares the two outputs, and `cli.test.ts`
 * holds FLAGS equal to the flags this text names.
 */

export const USAGE = `usage: ips-le [options] <file|dir>...
       ips-le [options] --stdin [--format <format>]
       ips-le mcp
       ips-le --version | --help

Finds every IP address, CIDR block and MAC address in a tree, normalizes
it and says what it is: loopback, private, link-local, cgnat, multicast,
broadcast, reserved, documentation, unique-local or global.

JSON, YAML, TOML, INI, dotenv, CSV and log files also carry the key each
address was found under. Every other file is still scanned — the search
runs over the bytes, so a .tf, a .rules or a rotated log yields its
addresses and only loses the key path.

IPv6 is normalized per RFC 5952, which is the reason to run this at all:
2001:0db8::0001 and 2001:db8::1 are one address, and a dedupe over the
raw text reports two.

One JSON report per line on stdout when it is piped or redirected, every
address listed on stderr.

It never resolves a name, never geolocates and never opens a socket. An
address it cannot read unambiguously is refused by name — ambiguous
version, malformed, octal hazard, integer form, prefix out of range,
MAC ambiguous — rather than guessed at.

Options:
  --format <format>    force a format instead of inferring it from the
                       file name; an unknown name still scans, it just
                       reports no key paths
  --kind <kind>        report only ipv4, ipv6, cidr or mac; repeatable
  --class <class>      report only one class, e.g. private or global;
                       repeatable
  --strict             exit 2 if anything was refused or any file could
                       not be read, rather than reporting it and
                       carrying on
  --stdin              read one document from stdin
  --hidden             walk hidden files and directories too
  --no-ignore          walk files that .gitignore excludes

A filter narrows what this tool claims, never what it declined to claim:
a refusal survives --kind and --class, because the finding a filtered
report would hide is the one most worth seeing.

A binary file — a NUL byte in its first 8 KiB, ripgrep's own test — is
never a text candidate: it produces no report line, is counted on
stderr, and never fails the run. A file that looked like text and could
not be read is named on stderr, carried in the report, and does not fail
the run by itself; --strict turns that one into a failure.

Exit codes follow grep: 0 addresses found · 1 none found · 2 malformed
question. Finding none is an answer, not an error, and so is a refusal.`;

export const FLAGS: readonly string[] = Object.freeze([
	'--format',
	'--kind',
	'--class',
	'--strict',
	'--stdin',
	'--hidden',
	'--no-ignore',
]);
