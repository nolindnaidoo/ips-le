//! A standing net over the scanner's three splitting rules and the
//! policy layer behind them.
//!
//! Time-boxed, not run to convergence: the point is that a panic, a
//! hang, or a slice off a character boundary has somewhere to be caught,
//! not that the input space is proved. Sixty seconds in CI, one second
//! locally, so the net is present on every push without owning the run.
//!
//! **It never reaches the network, and it never reads a file.** The
//! generated documents go to `extract_ips`, the MCP tool that takes
//! document text and touches no filesystem, so every case here is
//! `extract/` and nothing else.
//!
//! ## What it aims at
//!
//! `scanner.rs` keeps a log file's timestamps, ports, durations and
//! hashes out of the report with three rules, and every one of them is a
//! decision made on text somebody else wrote:
//!
//! - **a run glued to a name is part of that name** — `Ipv6Addr::from_str`
//!   contains `::f`, which is a valid IPv6 address;
//! - **a colon run splits unless it is IPv6-shaped** — `::`, seven
//!   colons, or six with a dotted tail;
//! - **a hyphen run splits unless it is a MAC** — six two-digit hex
//!   groups under one separator.
//!
//! Each rule slices a byte range out of the document and hands the parts
//! on. The generator writes the runs nobody writes by hand — an eighty
//! colon run, `::::::`, forty IPv6 groups, an address inside a URL
//! inside a timestamp — because a slice that lands off a character
//! boundary is a panic and a rule that never terminates is a hung CI
//! job.
//!
//! ## The one answer that is never allowed
//!
//! Every generated document carries `0177.0.0.99`, whose two readings
//! are `127.0.0.99` (octal) and `177.0.0.99` (decimal). **Neither may
//! appear in any answer, on either stream.** That is the whole octal
//! hazard: a tool that picked one would be the thing hiding the SSRF
//! bypass, and it must stay true under generated input and not only
//! under the cases somebody thought of.

use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::time::{Duration, Instant};

const BINARY: &str = env!("CARGO_BIN_EXE_ips-le");

/// The planted hazard and the two readings that must never appear.
const HAZARD: &str = "0177.0.0.99";
const OCTAL_READING: &str = "127.0.0.99";
const DECIMAL_READING: &str = "177.0.0.99";

/// One case may not take longer than this. A splitting rule that goes
/// quadratic on an eighty-colon run would otherwise be a CI job that
/// never ends.
const CASE_LIMIT: Duration = Duration::from_secs(20);

/// Every format the crate offers a key reader for, plus the fallback and
/// the absent case. The format decides only whether a finding carries a
/// key path, so cycling through them exercises seven readers against the
/// same hostile text.
const FORMATS: [Option<&str>; 9] = [
    Some("json"),
    Some("yaml"),
    Some("toml"),
    Some("ini"),
    Some("env"),
    Some("csv"),
    Some("log"),
    Some("handwriting"),
    None,
];

/// Seconds of fuzzing. CI passes 60; a bare `cargo test` runs one.
fn budget() -> Duration {
    let seconds = std::env::var("IPS_LE_FUZZ_SECONDS")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .unwrap_or(1);
    Duration::from_secs(seconds)
}

/// Printed on every run, failing or not: a fuzz failure nobody can
/// reproduce is a fuzz failure nobody fixes.
fn seed() -> u64 {
    std::env::var("IPS_LE_FUZZ_SEED")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .unwrap_or(0x1b5e_0b1d_2026_0812)
}

/// xorshift64*, four lines and identical on every platform. A fuzz run
/// needs to be reproducible, not statistically excellent.
struct Seeded(u64);

impl Seeded {
    fn next(&mut self) -> u64 {
        let mut state = self.0;
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        self.0 = state;
        state.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, limit: usize) -> usize {
        let limit = u64::try_from(limit).unwrap_or(1).max(1);
        usize::try_from(self.next() % limit).unwrap_or(0)
    }

    fn pick<'a, T>(&mut self, from: &'a [T]) -> &'a T {
        &from[self.below(from.len())]
    }
}

/// A server held open across the whole run: spawning a process per case
/// would measure `fork`, not the scanner.
struct Server {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<Option<String>>,
}

impl Server {
    fn start() -> Self {
        let mut child = Command::new(BINARY)
            .arg("mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the server starts");
        let stdin = child.stdin.take().expect("stdin");
        let stdout = child.stdout.take().expect("stdout");

        // Read on a thread so a case that never answers is a timeout
        // naming its body rather than a blocked test.
        let (sender, lines) = channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if sender.send(line.ok()).is_err() {
                    return;
                }
            }
            let _ = sender.send(None);
        });

        Self {
            child,
            stdin,
            lines,
        }
    }

    fn extract(&mut self, case: &str, arguments: &serde_json::Value) -> String {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "extract_ips", "arguments": arguments },
        });
        writeln!(self.stdin, "{request}")
            .unwrap_or_else(|error| panic!("{case}: the server stopped reading ({error})"));
        self.stdin
            .flush()
            .unwrap_or_else(|error| panic!("{case}: could not flush ({error})"));

        match self.lines.recv_timeout(CASE_LIMIT) {
            Ok(Some(line)) => line,
            Ok(None) => panic!("{case}: the server died — a panic, or a slice off a boundary"),
            Err(RecvTimeoutError::Timeout) => {
                panic!("{case}: no answer in {CASE_LIMIT:?} — a splitting rule is not terminating")
            }
            Err(RecvTimeoutError::Disconnected) => panic!("{case}: the server closed stdout"),
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ------------------------------------------------------------- generators

/// Runs aimed at **the colon rule**: IPv6-shaped enough to be handed
/// over whole, or not, and the shapes on the boundary between the two.
fn colon_run(seeded: &mut Seeded) -> String {
    match seeded.below(12) {
        0 => "::".to_string(),
        1 => ":".repeat(1 + seeded.below(80)),
        2 => "::::::".to_string(),
        // Forty groups: five times an address, and the parse must refuse
        // it rather than read the first eight.
        3 => (0..40)
            .map(|index| format!("{index:04x}"))
            .collect::<Vec<String>>()
            .join(":"),
        4 => format!("2001:db8{}1", "::".repeat(1 + seeded.below(20))),
        // Exactly seven colons — the shape that is handed over whole.
        5 => format!("{}:1", "0:".repeat(6)),
        // Six colons with a dotted tail: the uncompressed IPv4-embedded
        // form, and the other shape handed over whole.
        6 => format!("{}192.0.2.{}", "0:".repeat(6), seeded.below(256)),
        7 => format!(
            "[2001:db8::{}]:{}",
            seeded.below(65536),
            seeded.below(65536)
        ),
        8 => format!(
            "2026:{:02}:{:02}:{:02}",
            seeded.below(60),
            seeded.below(60),
            seeded.below(60)
        ),
        9 => format!("fe80::1%eth{}", seeded.below(10)),
        10 => format!("{}::", "f".repeat(1 + seeded.below(40))),
        _ => format!("127.0.0.1:{}", seeded.below(65536)),
    }
}

/// Runs aimed at **the hyphen rule**: a MAC is six two-digit hex groups
/// under one separator, and everything else has to come apart.
fn hyphen_run(seeded: &mut Seeded) -> String {
    match seeded.below(9) {
        0 => "aa-bb-cc-dd-ee-ff".to_string(),
        1 => "aa:bb-cc:dd-ee:ff".to_string(),
        2 => "-".repeat(1 + seeded.below(60)),
        3 => format!("{}ff", "aa-".repeat(1 + seeded.below(30))),
        4 => "2026-08-12".to_string(),
        5 => format!("10.0.0.{}-10.0.0.{}", seeded.below(256), seeded.below(256)),
        6 => "deadbeefcafe".to_string(),
        7 => format!("{:012x}", seeded.next()),
        _ => format!("-10.0.0.{}-", seeded.below(256)),
    }
}

/// Runs aimed at **the glue rule**: a run touching an identifier belongs
/// to that identifier, unless a single separator stands between them.
fn glued_run(seeded: &mut Seeded) -> String {
    match seeded.below(9) {
        0 => "std::net::Ipv6Addr".to_string(),
        1 => "Vec::<u8>::new".to_string(),
        2 => format!("v1.2.3.{}", seeded.below(100)),
        3 => format!("x10.0.0.{}", seeded.below(256)),
        4 => format!("10.0.0.{}z", seeded.below(256)),
        5 => format!("client_ip:10.0.0.{}", seeded.below(256)),
        6 => format!("from=10.0.0.{}", seeded.below(256)),
        7 => format!("{}::f", "a".repeat(1 + seeded.below(40))),
        _ => format!("Ipv4Addr::from_str(\"10.0.0.{}\")", seeded.below(256)),
    }
}

/// The bypasses: every octal spelling, and the integer forms. **None of
/// these may ever come back resolved**, which is the property the whole
/// refusal design rests on.
fn bypass(seeded: &mut Seeded) -> String {
    match seeded.below(10) {
        0 => "010.1.1.1".to_string(),
        1 => "0177.0.0.1".to_string(),
        2 => "192.168.001.1".to_string(),
        3 => format!("{}10.0.0.1", "0".repeat(1 + seeded.below(20))),
        4 => "0.0.0.0".to_string(),
        5 => "2130706433".to_string(),
        6 => "3232235777".to_string(),
        7 => format!("{}", seeded.next() % u64::from(u32::MAX)),
        8 => "00.00.00.00".to_string(),
        _ => "010.0.0.0/8".to_string(),
    }
}

/// Prefixes far outside both families, and prefixes that are not
/// numbers at all.
fn prefixed(seeded: &mut Seeded) -> String {
    let base = match seeded.below(4) {
        0 => "10.0.0.0".to_string(),
        1 => "2001:db8::".to_string(),
        2 => "::".to_string(),
        _ => format!("192.168.{}.0", seeded.below(256)),
    };
    let prefix = match seeded.below(9) {
        0 => "0".to_string(),
        1 => "32".to_string(),
        2 => "33".to_string(),
        3 => "128".to_string(),
        4 => "129".to_string(),
        5 => "999".to_string(),
        6 => "99999999999999999999".to_string(),
        7 => String::new(),
        _ => "abc".to_string(),
    };
    format!("{base}/{prefix}")
}

/// Addresses inside the things a log line is actually made of.
fn embedded(seeded: &mut Seeded) -> String {
    match seeded.below(8) {
        0 => format!("postgres://user:pw@10.0.0.{}:5432/app", seeded.below(256)),
        1 => format!("http://[2001:db8::{}]:8080/api/v2", seeded.below(65536)),
        2 => format!(
            "[12/Aug/2026:10:30:{:02} +0000] \"GET /x\" 200",
            seeded.below(60)
        ),
        3 => format!("2026-08-12T10:30:{:02}.250Z", seeded.below(60)),
        4 => format!("http://10.0.0.{}/24", seeded.below(256)),
        5 => format!("::ffff:169.254.169.{}", seeded.below(256)),
        6 => format!("elapsed 00:00:0{}.250", seeded.below(10)),
        _ => format!("sha256:{:064x}", seeded.next()),
    }
}

fn token(seeded: &mut Seeded) -> String {
    match seeded.below(6) {
        0 => colon_run(seeded),
        1 => hyphen_run(seeded),
        2 => glued_run(seeded),
        3 => bypass(seeded),
        4 => prefixed(seeded),
        _ => embedded(seeded),
    }
}

/// One document. The wrapping is deliberately varied — logfmt pairs,
/// JSON, YAML, CSV, bare prose — because the key reader decides the
/// `Context` the policy layer sees, and a refusal is conditional on it.
fn document(seeded: &mut Seeded) -> String {
    let mut out = String::new();
    if seeded.below(8) == 0 {
        out.push('\u{feff}');
    }
    let newline = if seeded.below(4) == 0 { "\r\n" } else { "\n" };

    // Always planted, always at a position the generator does not
    // choose: the one answer that may never come back resolved.
    let _ = write!(out, "bind_ip={HAZARD}{newline}");

    for index in 0..=seeded.below(20) {
        let token = token(seeded);
        let _ = match seeded.below(7) {
            0 => write!(out, "  \"peer{index}_ip\": \"{token}\",{newline}"),
            1 => write!(out, "  peer{index}_addr: {token}{newline}"),
            2 => write!(out, "PEER{index}_HOST={token}{newline}"),
            3 => write!(out, "{index},{token},ok{newline}"),
            4 => write!(out, "ts=2026-08-12 remote_addr={token} status=200{newline}"),
            5 => write!(out, "# a comment holding {token}{newline}"),
            _ => write!(out, "the value {token} appears in prose{newline}"),
        };
    }

    if seeded.below(2) == 0 {
        while out.ends_with('\n') || out.ends_with('\r') {
            out.pop();
        }
    }
    out
}

// ---------------------------------------------------------------- checking

/// Every field the schema promises, on every finding. A consumer writes
/// one reader, so a missing key is a contract break rather than a
/// cosmetic one.
const FIELDS: [&str; 9] = [
    "kind",
    "text",
    "line",
    "column",
    "key",
    "normalized",
    "class",
    "cidr",
    "refused",
];

fn check(case: &str, document: &str, raw: &str) {
    let response: serde_json::Value = serde_json::from_str(raw)
        .unwrap_or_else(|error| panic!("{case}: the answer is not JSON ({error}) — {raw}"));
    assert!(
        response.get("error").is_none(),
        "{case}: the tool call failed — {raw}\ndocument:\n{document}"
    );
    let envelope = &response["result"]["structuredContent"];
    assert_eq!(
        envelope["meta"]["tool"], "extract_ips",
        "{case}: not the tool's envelope — {raw}"
    );
    assert_eq!(envelope["ok"], true, "{case}: the scan did not run — {raw}");
    assert!(
        envelope["meta"]["truncated"].is_boolean(),
        "{case}: truncated is not a boolean — {raw}"
    );

    let addresses = envelope["data"]["addresses"]
        .as_array()
        .unwrap_or_else(|| panic!("{case}: addresses is not a list — {raw}"));

    for found in addresses {
        for field in FIELDS {
            assert!(
                found.get(field).is_some(),
                "{case}: {field} is missing from {found}"
            );
        }
        let text = found["text"]
            .as_str()
            .unwrap_or_else(|| panic!("{case}: a finding has no text — {found}"));
        assert!(!text.is_empty(), "{case}: an empty finding — {found}");
        assert!(
            document.contains(text),
            "{case}: {text:?} was reported and is not in the document\n{document}"
        );
        assert!(
            found["line"].as_u64().is_some_and(|line| line >= 1),
            "{case}: line is not 1-based — {found}"
        );
        assert!(
            found["column"].as_u64().is_some_and(|column| column >= 1),
            "{case}: column is not 1-based — {found}"
        );

        // A refusal never carries an answer. The moment a `normalized`
        // appears beside one, the flag is gone and only the claim is
        // left.
        if !found["refused"].is_null() {
            assert!(
                found["normalized"].is_null() && found["class"].is_null(),
                "{case}: a refusal carries a reading — {found}"
            );
            assert!(
                found["refused"]["reason"].is_string(),
                "{case}: a refusal with no reason — {found}"
            );
        }
    }

    let refused = addresses
        .iter()
        .filter(|found| !found["refused"].is_null())
        .count();
    assert_eq!(
        envelope["data"]["refused"].as_u64(),
        u64::try_from(refused).ok(),
        "{case}: the refusal count disagrees with the findings — {raw}"
    );

    forbidden_readings(case, raw);
}

/// **The octal hazard, checked on whatever stream it was given.** The
/// hazard's own text contains its decimal reading as a substring, so
/// that text is removed before looking — the same way `contracts.rs`
/// does it.
fn forbidden_readings(case: &str, stream: &str) {
    assert!(
        !stream.contains(OCTAL_READING),
        "{case}: the octal reading {OCTAL_READING} was resolved — {stream}"
    );
    assert!(
        !stream.replace(HAZARD, "").contains(DECIMAL_READING),
        "{case}: the decimal reading {DECIMAL_READING} was resolved — {stream}"
    );
}

// ------------------------------------------------------------------- tests

#[test]
fn the_scanner_survives_what_grows_out_of_its_own_splitting_rules() {
    let seed = seed();
    let budget = budget();
    eprintln!("fuzz: seed {seed:#x}, budget {budget:?}");

    let mut server = Server::start();
    let mut seeded = Seeded(seed);
    let mut cases = 0usize;

    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        let body = document(&mut seeded);
        let format = *seeded.pick(&FORMATS);
        let case = format!("seed {seed:#x} case {cases} format {format:?}");

        let mut arguments = serde_json::json!({
            "content": body,
            // Above the default cap, so the answer is the whole answer
            // and every finding can be held to the document it came
            // from.
            "maxResults": 5000,
        });
        if let Some(format) = format {
            arguments["format"] = serde_json::json!(format);
        }

        let raw = server.extract(&case, &arguments);
        check(&case, &body, &raw);
        cases += 1;
    }

    eprintln!("fuzz: {cases} documents, seed {seed:#x}");
    assert!(cases > 0, "the fuzzer ran no documents");
}

/// The shapes by name, outside the random path, so a failure says what
/// broke rather than which seed found it. Every one of them is a run the
/// scanner has to either hold together or take apart, at a size nobody
/// writes by hand.
#[test]
fn pathological_runs_terminate() {
    let mut server = Server::start();
    let cases: Vec<(&str, String)> = vec![
        ("ten thousand colons", ":".repeat(10_000)),
        ("five thousand double colons", "::".repeat(5_000)),
        ("a hex run of a hundred thousand", "a".repeat(100_000)),
        ("an alternating separator run", "a:1-2.".repeat(20_000)),
        (
            "forty thousand IPv6 groups",
            (0..40_000)
                .map(|index| format!("{:04x}", index % 65536))
                .collect::<Vec<String>>()
                .join(":"),
        ),
        (
            "ten thousand addresses on one line",
            (0..10_000)
                .map(|index| format!("peer{index}_ip=10.0.0.{}", index % 256))
                .collect::<Vec<String>>()
                .join(" "),
        ),
        (
            "ten thousand hazards on one line",
            format!("{HAZARD} ").repeat(10_000),
        ),
        (
            "a prefix of twenty thousand digits",
            format!("10.0.0.0/{}", "9".repeat(20_000)),
        ),
        (
            "one address glued to a hundred thousand identifier bytes",
            format!("{}::f10.0.0.1", "n".repeat(100_000)),
        ),
    ];

    for (name, body) in cases {
        let started = Instant::now();
        let raw = server.extract(
            name,
            &serde_json::json!({ "content": body, "maxResults": 5000 }),
        );
        check(name, &body, &raw);
        eprintln!("fuzz: {name} answered in {:?}", started.elapsed());
    }
}

/// The same generated corpus through the **terminal** surface, because
/// "never on either stream" is a claim about stdout *and* the human
/// projection on stderr — and stderr is the one a person actually reads.
#[test]
fn an_octal_hazard_survives_the_fuzzer_on_both_streams() {
    const DOCUMENTS: usize = 200;

    let seed = seed();
    let mut seeded = Seeded(seed);
    let mut corpus = String::new();
    for _ in 0..DOCUMENTS {
        corpus.push_str(&document(&mut seeded));
        corpus.push('\n');
    }

    let mut child = Command::new(BINARY)
        .args(["--stdin", "--format", "log"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary runs");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(corpus.as_bytes())
        .expect("writes");
    let output = child.wait_with_output().expect("the child finishes");

    assert!(
        matches!(output.status.code(), Some(0 | 1)),
        "the run did not finish cleanly: {:?}",
        output.status
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    forbidden_readings("stdout", &stdout);
    forbidden_readings("stderr", &stderr);

    // And the hazard was actually seen, or the assertion above is
    // vacuous.
    assert!(
        stderr.contains("refused"),
        "the corpus produced no refusal at all: {stderr}"
    );
    eprintln!("fuzz: {DOCUMENTS} documents through the CLI, seed {seed:#x}");
}
