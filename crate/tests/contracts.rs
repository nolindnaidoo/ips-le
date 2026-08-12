//! The exit codes and the stdout contract, driven against the built
//! binary.
//!
//! These are the API: a shell branches on the exit code and parses
//! stdout, so both are pinned here rather than inferred from unit tests
//! of the functions behind them. Nothing here needs a network or a
//! privileged filesystem operation, so it runs everywhere on every
//! push.
//!
//! A new refusal adds its case here.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

const BINARY: &str = env!("CARGO_BIN_EXE_ips-le");
const CRATE: &str = env!("CARGO_MANIFEST_DIR");
const README: &str = include_str!("../README.md");
static COUNTER: AtomicUsize = AtomicUsize::new(0);

struct Tree {
    root: PathBuf,
}

impl Tree {
    fn new(name: &str) -> Self {
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "ips-le-contract-{name}-{}-{unique}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("a temporary directory");
        Self {
            root: std::fs::canonicalize(&root).expect("a canonical directory"),
        }
    }

    fn path(&self) -> &Path {
        &self.root
    }

    fn write(&self, relative: &str, contents: &str) -> PathBuf {
        self.write_bytes(relative, contents.as_bytes())
    }

    fn write_bytes(&self, relative: &str, contents: &[u8]) -> PathBuf {
        let target = self.root.join(relative);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).expect("a parent directory");
        }
        std::fs::write(&target, contents).expect("a file");
        target
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run(args: &[&str]) -> Run {
    let output = Command::new(BINARY)
        .args(args)
        .output()
        .expect("the binary runs");
    Run {
        code: output.status.code().expect("an exit code"),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn pipe(args: &[&str], input: &str) -> Run {
    let mut child = Command::new(BINARY)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary runs");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("writes");
    let output = child.wait_with_output().expect("finishes");
    Run {
        code: output.status.code().expect("an exit code"),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// Every line of stdout, parsed. Doubles as the assertion that stdout
/// is JSON Lines and nothing else — a stray human message there would
/// fail to parse.
fn reports(run: &Run) -> Vec<serde_json::Value> {
    run.stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("stdout carries only JSON"))
        .collect()
}

fn findings(run: &Run) -> Vec<serde_json::Value> {
    reports(run)
        .into_iter()
        .flat_map(|report| report["addresses"].as_array().cloned().unwrap_or_default())
        .collect()
}

/// A config, a log, a file this crate has no reader for, and prose.
fn audit_tree(name: &str) -> Tree {
    let tree = Tree::new(name);
    tree.write("app.yaml", "server:\n  bind: 10.0.0.5\n  version: 1.2.3\n");
    tree.write("logs/access.log", "remote_addr=203.0.113.45 status=200\n");
    tree.write("infra/main.tf", "cidr_block = \"10.0.0.0/16\"\n");
    tree.write("NOTES.md", "no addresses in this prose at all\n");
    tree
}

#[test]
fn a_tree_with_addresses_exits_zero() {
    let tree = audit_tree("found");
    let run = run(&[&tree.path().to_string_lossy()]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    let total: u64 = reports(&run)
        .iter()
        .filter_map(|report| report["summary"]["addresses"].as_u64())
        .sum();
    assert_eq!(
        total, 3,
        "the bind address, the log's client, and the Terraform block"
    );
}

/// grep's convention, and the reason it is worth having: finding
/// nothing is an answer, not an error.
#[test]
fn a_tree_with_none_exits_one() {
    let tree = Tree::new("none");
    tree.write("docs/a.md", "no addresses here\n");
    let run = run(&[&tree.path().to_string_lossy()]);
    assert_eq!(run.code, 1);
    assert!(run.stderr.contains("0 addresses"), "{}", run.stderr);
}

/// A malformed question — not a malformed answer.
#[test]
fn a_bad_invocation_exits_two() {
    for args in [
        vec!["--nope", "."],
        vec!["--kind", "ipv5", "."],
        vec!["--class", "public", "."],
        vec!["--format"],
        vec![],
    ] {
        let run = run(&args);
        assert_eq!(run.code, 2, "{args:?} -> {}", run.stderr);
        assert!(run.stdout.is_empty(), "{args:?} wrote to stdout");
        assert!(run.stderr.starts_with("ips-le:"), "{}", run.stderr);
    }
}

/// stdout is protocol. Every field the schema promises is on every
/// finding, nulls included, so a consumer writes one reader.
#[test]
fn every_report_carries_the_whole_schema() {
    let tree = audit_tree("schema");
    let run = run(&[&tree.path().to_string_lossy()]);
    for report in reports(&run) {
        assert_eq!(report["schema"], 1);
        for field in ["file", "format", "addresses", "diagnostics", "summary"] {
            assert!(report.get(field).is_some(), "{field} is missing");
        }
        assert!(report["summary"]["addresses"].is_number());
        assert!(report["summary"]["refused"].is_number());
    }
    for found in findings(&run) {
        for field in [
            "kind",
            "text",
            "line",
            "column",
            "key",
            "normalized",
            "class",
            "cidr",
            "refused",
        ] {
            assert!(
                found.get(field).is_some(),
                "{field} is missing from {found}"
            );
        }
    }
}

/// The whole contract in one assertion: four spellings of one address
/// come back as one normalized form, which is what a dedupe over the
/// raw text cannot do.
#[test]
fn ipv6_is_normalized_per_rfc_5952() {
    let document = "a: 2001:0db8:0000:0000:0000:0000:0000:0001\n\
                    b: 2001:db8:0:0:0:0:0:1\n\
                    c: 2001:0db8::0001\n\
                    d: 2001:DB8::1\n";
    let run = pipe(&["--stdin", "--format", "yaml"], document);
    let normalized: Vec<String> = findings(&run)
        .iter()
        .filter_map(|found| found["normalized"].as_str().map(str::to_string))
        .collect();
    assert_eq!(normalized, ["2001:db8::1"; 4]);
}

/// A refusal is a finding, not a failure — until `--strict` says
/// otherwise.
#[test]
fn a_refusal_does_not_move_the_exit_code_unless_strict() {
    let tree = Tree::new("refusal");
    tree.write("hosts.env", "BIND_IP=010.1.1.1\n");
    let path = tree.path().to_string_lossy().into_owned();

    let lenient = run(&[&path]);
    assert_eq!(lenient.code, 1, "nothing was named, so nothing was found");
    let found = &findings(&lenient)[0];
    assert_eq!(found["refused"]["reason"], "octal_hazard");
    assert_eq!(found["normalized"], serde_json::Value::Null);
    assert!(lenient.stderr.contains("1 refused"), "{}", lenient.stderr);

    let strict = run(&["--strict", &path]);
    assert_eq!(strict.code, 2);
}

/// Every refusal reason reachable from the command line, in one file.
/// A new reason adds its line here.
#[test]
fn every_refusal_reason_reaches_the_command_line() {
    let tree = Tree::new("reasons");
    tree.write(
        "hazards.env",
        "A=010.1.1.1\n\
         B=10.0.1\n\
         C=256.1.1.1\n\
         D=10.0.0.0/33\n\
         E=deadbeefcafe\n\
         BIND_IP=2130706433\n",
    );
    let run = run(&[&tree.path().to_string_lossy()]);
    let reasons: Vec<String> = findings(&run)
        .iter()
        .filter_map(|found| found["refused"]["reason"].as_str().map(str::to_string))
        .collect();
    assert_eq!(
        reasons,
        [
            "octal_hazard",
            "ambiguous_version",
            "malformed_address",
            "prefix_out_of_range",
            "mac_ambiguous",
            "integer_form",
        ]
    );
}

/// The octal hazard is the one refusal whose value is entirely in *not*
/// answering, so the output is checked for the answers it must not
/// contain.
#[test]
fn an_octal_hazard_is_never_resolved_on_either_stream() {
    let run = pipe(&["--stdin"], "010.1.1.1\n");
    assert!(!run.stdout.contains("8.1.1.1"), "{}", run.stdout);
    assert!(!run.stderr.contains("8.1.1.1"), "{}", run.stderr);
    assert!(
        !run.stdout.replace("010.1.1.1", "").contains("10.1.1.1"),
        "{}",
        run.stdout
    );
}

/// The audit case: a file this crate has no reader for still yields its
/// addresses, and only loses the key path.
#[test]
fn a_file_with_no_reader_still_yields_its_addresses() {
    let tree = audit_tree("fallback");
    let terraform = reports(&run(&[&tree.path().to_string_lossy()]))
        .into_iter()
        .find(|report| {
            report["file"]
                .as_str()
                .unwrap_or_default()
                .contains("main.tf")
        })
        .expect("the Terraform file was read");
    assert_eq!(terraform["format"], "unknown");
    assert_eq!(terraform["addresses"][0]["normalized"], "10.0.0.0/16");
    assert_eq!(terraform["addresses"][0]["key"], serde_json::Value::Null);
    assert_eq!(terraform["addresses"][0]["cidr"]["hosts"], "65536");
}

#[test]
fn a_filter_narrows_the_answer_and_keeps_the_refusals() {
    let document = "8.8.8.8 10.0.0.1 010.1.1.1 aa:bb:cc:dd:ee:ff\n";
    let run = pipe(&["--stdin", "--class", "global"], document);
    let texts: Vec<String> = findings(&run)
        .iter()
        .filter_map(|found| found["text"].as_str().map(str::to_string))
        .collect();
    assert_eq!(texts, ["8.8.8.8", "010.1.1.1", "aa:bb:cc:dd:ee:ff"]);
}

#[test]
fn a_binary_file_is_counted_and_never_fails_the_run() {
    let tree = Tree::new("binary");
    tree.write_bytes("logo.png", &[0x89, 0x50, 0x4e, 0x47, 0x00, 0x1a]);
    tree.write("app.env", "BIND=10.0.0.1\n");
    let run = run(&["--strict", &tree.path().to_string_lossy()]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert_eq!(reports(&run).len(), 1, "the PNG produced no report line");
    assert!(
        run.stderr.contains("1 binary file skipped"),
        "{}",
        run.stderr
    );
}

#[test]
fn stdin_reads_one_document() {
    let run = pipe(&["--stdin", "--format", "log"], "src=10.0.0.1 ok\n");
    assert_eq!(run.code, 0);
    let reports = reports(&run);
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0]["file"], "<stdin>");
    assert_eq!(reports[0]["addresses"][0]["key"], "src");
}

/// **The README's sample output is a claim, so it is checked.** It
/// showed four of eight findings as though it were the whole answer and
/// then went stale against the fixture it names — which is the exact
/// shape of the thing this crate exists to stop, a plausible report
/// nobody re-ran.
///
/// The block is matched against a real run rather than eyeballed. It is
/// stderr, because that is the human projection the README is showing.
#[test]
fn the_readme_sample_is_what_the_binary_actually_prints() {
    let sample = README
        .split("```")
        .find(|block| block.starts_with("\nfixtures/documents/network.yaml:"))
        .expect("the README carries the sample output block")
        .trim();

    let output = Command::new(BINARY)
        .arg("fixtures/documents/network.yaml")
        .current_dir(CRATE)
        .output()
        .expect("the binary runs");
    assert_eq!(output.status.code(), Some(0));
    let actual = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        sample,
        actual.trim(),
        "the README sample no longer matches the tool's own output"
    );
}

#[test]
fn help_and_version_answer_and_exit_zero() {
    let help = run(&["--help"]);
    assert_eq!(help.code, 0);
    assert!(help.stdout.contains("usage: ips-le"), "{}", help.stdout);
    let version = run(&["--version"]);
    assert_eq!(version.code, 0);
    assert!(
        version.stdout.starts_with("ips-le 0."),
        "{}",
        version.stdout
    );
}

/// The two surfaces are one implementation, and this is the assertion
/// that keeps them that way.
#[test]
fn the_mcp_surface_answers_what_the_cli_answers() {
    let tree = Tree::new("parity");
    tree.write("app.yaml", "bind: 10.0.0.5\npeer: 2001:0db8::0001\n");
    let path = tree.path().to_string_lossy().into_owned();

    let cli = reports(&run(&[&path]));
    let frame = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": "ips_le_scan", "arguments": { "path": path } },
    });
    let mcp = pipe(&["mcp"], &format!("{frame}\n"));
    let reply: serde_json::Value =
        serde_json::from_str(mcp.stdout.trim()).expect("the server answers JSON");
    assert_eq!(
        reply["result"]["structuredContent"]["data"]["reports"],
        serde_json::Value::Array(cli),
        "the two surfaces disagree"
    );
}
