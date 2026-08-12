//! The terminal surface.
//!
//! stdout is always protocol — one JSON report per line, one line per
//! file. stderr is always for the human, and is a projection of the
//! same reports rather than parallel prose. There is no `--json` flag:
//! one mode, nothing to misremember, and the human summary cannot drift
//! from the machine one because it is derived from it.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use crate::extract::{Class, Kind, resolve_format};
use crate::scan::{self, FileReport, ScanOptions};
use crate::walk::{self, WalkOptions};

const USAGE: &str = "usage: ips-le [options] <file|dir>...
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
question. Finding none is an answer, not an error, and so is a refusal.";

/// Every flag the parser accepts. Held equal to the flags named in
/// USAGE by a test, and consulted at runtime so the list is what the
/// parser actually honours.
const FLAGS: [&str; 7] = [
    "--format",
    "--kind",
    "--class",
    "--strict",
    "--stdin",
    "--hidden",
    "--no-ignore",
];

#[derive(Debug)]
struct Cli {
    /// Fail the run on a refusal or an unreadable file.
    strict: bool,
    inputs: Vec<PathBuf>,
    stdin: bool,
    scan: ScanOptions,
    walk: WalkOptions,
}

pub(crate) fn run() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if let Some(first) = args.first() {
        match first.as_str() {
            "mcp" => return crate::mcp::serve(),
            "--help" | "-h" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            "--version" | "-V" => {
                println!("ips-le {}", env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            _ => {}
        }
    }

    match execute(&args) {
        Ok(code) => ExitCode::from(code),
        Err(message) => {
            eprintln!("ips-le: {message}");
            ExitCode::from(2)
        }
    }
}

fn execute(args: &[String]) -> Result<u8, String> {
    let options = parse(args)?;
    let (reports, binary) = if options.stdin {
        (vec![scan_stdin(&options)?], 0)
    } else {
        let walked = walk::collect(&options.inputs, &options.walk)?;
        let scanned = walked
            .files
            .iter()
            .map(|target| scan::scan_file(target, &options.scan))
            .collect();
        let (mut reports, binary) = scan::partition(scanned);
        // A path the walk could not open is a report line, not the end
        // of the run: one locked directory must not take the audit of
        // everything beside it with it, and must not vanish either.
        reports.extend(
            walked
                .unreadable
                .iter()
                .map(|(path, reason)| scan::unreadable(path, reason)),
        );
        (reports, binary)
    };

    write_reports(&reports)?;
    summarise(&reports, binary);
    Ok(scan::exit_code(&reports, options.strict))
}

fn write_reports(reports: &[FileReport]) -> Result<(), String> {
    let mut stdout = std::io::stdout().lock();
    for report in reports {
        let line = serde_json::to_string(report).expect("a report serializes");
        writeln!(stdout, "{line}")
            .map_err(|error| format!("could not write the report: {error}"))?;
    }
    Ok(())
}

fn scan_stdin(options: &Cli) -> Result<FileReport, String> {
    let mut content = String::new();
    std::io::stdin()
        .read_to_string(&mut content)
        .map_err(|error| format!("could not read stdin: {error}"))?;
    // No filename to infer from, so an unnamed format falls back to the
    // byte scan — which still finds every address, and is why this is
    // not a refusal.
    let format = options
        .scan
        .format
        .unwrap_or(crate::extract::FALLBACK_FORMAT);
    Ok(scan::scan_content(
        scan::without_bom(&content),
        "<stdin>".to_string(),
        format,
        &options.scan,
    ))
}

fn parse(args: &[String]) -> Result<Cli, String> {
    let mut options = Cli {
        inputs: Vec::new(),
        stdin: false,
        strict: false,
        scan: ScanOptions::default(),
        walk: WalkOptions::default(),
    };

    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        // Strict parsing, never a silent default: a typo'd `--clas`
        // that quietly did nothing would produce a report the caller
        // believed was filtered.
        if arg.starts_with('-') && !FLAGS.contains(&arg.as_str()) {
            return Err(format!("{arg} is not an option. Try --help."));
        }

        match arg.as_str() {
            "--stdin" => options.stdin = true,
            "--strict" => options.strict = true,
            "--hidden" => options.walk.hidden = true,
            "--no-ignore" => options.walk.respect_ignore = false,
            // An unknown format still scans — the bytes do not care —
            // so this one is lenient where the filters are not. The
            // flag still takes a value, and a missing one is a refusal.
            "--format" => {
                let value = value_for("--format", &mut rest)?;
                options.scan.format = Some(resolve_format(Some(value), None));
            }
            // A filter names what comes back, so a name nobody
            // recognises has to be an error: silently reporting
            // everything would answer a question that was not asked.
            "--kind" => {
                let value = value_for("--kind", &mut rest)?;
                let kind = Kind::parse(&value.to_lowercase()).ok_or_else(|| {
                    format!("{value} is not a kind. Try {}.", Kind::ALL.join(", "))
                })?;
                options.scan.kinds.push(kind);
            }
            "--class" => {
                let value = value_for("--class", &mut rest)?;
                let class = Class::parse(&value.to_lowercase()).ok_or_else(|| {
                    format!("{value} is not a class. Try {}.", Class::ALL.join(", "))
                })?;
                options.scan.classes.push(class);
            }
            path => options.inputs.push(PathBuf::from(path)),
        }
    }

    if options.stdin && !options.inputs.is_empty() {
        return Err("reading from stdin takes no file arguments".to_string());
    }
    if !options.stdin && options.inputs.is_empty() {
        return Err("name a file or a directory to read. Try --help.".to_string());
    }
    Ok(options)
}

fn value_for<'a>(
    flag: &str,
    rest: &mut impl Iterator<Item = &'a String>,
) -> Result<&'a str, String> {
    rest.next()
        .map(String::as_str)
        .ok_or_else(|| format!("{flag} needs a value"))
}

/// The human half. Every line restates something already on stdout —
/// except the binary count, which is the one thing stdout cannot carry
/// because those files produce no report line at all.
fn summarise(reports: &[FileReport], binary: usize) {
    let mut stderr = std::io::stderr().lock();
    let mut addresses = 0;
    let mut refused = 0;

    for report in reports {
        for diagnostic in &report.diagnostics {
            let _ = writeln!(stderr, "{}: {}", report.file, diagnostic.message);
        }
        for found in &report.addresses {
            let _ = writeln!(stderr, "{}", scan::describe(report, found));
        }
        addresses += report.summary.addresses;
        refused += report.summary.refused;
    }

    let _ = writeln!(
        stderr,
        "{} in {}",
        plural(addresses, "address", "addresses"),
        plural(reports.len(), "file", "files")
    );
    if refused > 0 {
        // Never silent. A reader treating the address list as complete
        // has to know how much of the document this declined to name.
        let _ = writeln!(stderr, "{refused} refused");
    }
    if binary > 0 {
        let _ = writeln!(
            stderr,
            "{} skipped",
            plural(binary, "binary file", "binary files")
        );
    }
}

fn plural(count: usize, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::SUPPORTED_FORMATS;

    #[test]
    fn every_documented_flag_is_parsed_and_the_reverse() {
        let mut documented: Vec<&str> = USAGE
            .split_whitespace()
            .filter(|word| word.starts_with("--"))
            .map(|word| word.trim_end_matches([',', '.', ':', ';']))
            .filter(|word| !matches!(*word, "--version" | "--help"))
            .collect();
        documented.sort_unstable();
        documented.dedup();

        let mut implemented = FLAGS.to_vec();
        implemented.sort_unstable();
        assert_eq!(documented, implemented);
    }

    #[test]
    fn the_parser_accepts_every_flag_it_lists() {
        for flag in FLAGS {
            let args: Vec<String> = match flag {
                "--format" => vec![flag.into(), "json".into(), "x".into()],
                "--kind" => vec![flag.into(), "ipv4".into(), "x".into()],
                "--class" => vec![flag.into(), "private".into(), "x".into()],
                "--stdin" => vec![flag.into()],
                _ => vec![flag.into(), "x".into()],
            };
            assert!(parse(&args).is_ok(), "{flag}");
        }
    }

    #[test]
    fn an_unknown_flag_is_refused_rather_than_ignored() {
        let error = parse(&["--clas".into(), "x".into()]).expect_err("a refusal");
        assert!(error.contains("--clas"), "{error}");
    }

    /// The asymmetry, stated as a test. A format nobody recognises is
    /// still a scan; a filter nobody recognises is a question this tool
    /// cannot answer, and answering it with everything would be the
    /// wrong kind of helpful.
    #[test]
    fn an_unknown_format_falls_back_and_an_unknown_filter_does_not() {
        let options = parse(&["--format".into(), "handwriting".into(), "x".into()])
            .expect("a format falls back");
        assert_eq!(options.scan.format, Some(crate::extract::FALLBACK_FORMAT));

        let error = parse(&["--kind".into(), "ipv5".into(), "x".into()]).expect_err("a refusal");
        assert!(error.contains("ipv4"), "{error}");
        let error = parse(&["--class".into(), "public".into(), "x".into()]).expect_err("a refusal");
        assert!(error.contains("global"), "{error}");
    }

    #[test]
    fn every_offered_format_kind_and_class_is_accepted_by_name() {
        for format in SUPPORTED_FORMATS {
            let options = parse(&["--format".into(), format.into(), "x".into()]).expect(format);
            assert_eq!(options.scan.format, Some(format));
        }
        for kind in Kind::ALL {
            assert!(
                parse(&["--kind".into(), kind.into(), "x".into()]).is_ok(),
                "{kind}"
            );
        }
        for class in Class::ALL {
            assert!(
                parse(&["--class".into(), class.into(), "x".into()]).is_ok(),
                "{class}"
            );
        }
    }

    #[test]
    fn a_filter_is_repeatable() {
        let options = parse(&[
            "--kind".into(),
            "ipv4".into(),
            "--kind".into(),
            "ipv6".into(),
            "x".into(),
        ])
        .expect("accepted");
        assert_eq!(options.scan.kinds, [Kind::Ipv4, Kind::Ipv6]);
    }

    #[test]
    fn a_flag_with_no_value_is_refused() {
        for flag in ["--format", "--kind", "--class"] {
            assert!(parse(&[flag.into()]).is_err(), "{flag}");
        }
    }

    /// There is no verdict, and no flag that would produce one. This
    /// tool says what an address *is*, never whether it should be
    /// there.
    #[test]
    fn no_flag_asks_for_a_judgment_or_reaches_the_network() {
        for attempt in ["--resolve", "--dns", "--geo", "--whois", "--fix", "--allow"] {
            assert!(
                parse(&[attempt.into(), "x".into()]).is_err(),
                "{attempt} was accepted"
            );
        }
        for word in ["--resolve", "--dns", "--geo", "--whois", "--ping"] {
            assert!(!USAGE.contains(word), "the usage text offers {word}");
        }
    }

    /// The usage text has to name every class, or `--class` is a flag
    /// whose values are only discoverable by being wrong.
    #[test]
    fn the_usage_text_names_the_vocabulary_and_the_exit_codes() {
        for class in Class::ALL {
            assert!(USAGE.contains(class), "the usage text omits {class}");
        }
        for kind in Kind::ALL {
            assert!(USAGE.contains(kind), "the usage text omits {kind}");
        }
        assert!(USAGE.contains("grep"));
        assert!(USAGE.contains("RFC 5952"));
        for code in ["0", "1", "2"] {
            assert!(USAGE.contains(code), "exit code {code} is undocumented");
        }
    }

    #[test]
    fn naming_nothing_is_refused() {
        assert!(parse(&[]).is_err());
    }

    #[test]
    fn stdin_and_file_arguments_together_are_refused() {
        assert!(parse(&["--stdin".into(), "x".into()]).is_err());
    }
}
