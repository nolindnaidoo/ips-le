//! Behaviour that differs by operating system, asserted rather than
//! hoped.
//!
//! Everything here runs the **built binary** on all three platforms. A
//! case that cannot be constructed on one of them says so by name and
//! keeps asserting whatever the platform did instead — a reserved
//! Windows filename that could not be created still has to leave the
//! walk standing. **A skip is never reported as a pass.**
//!
//! The case this file exists for: a sibling in this family shipped a
//! release whose report used `\` on Windows and `/` everywhere else, red
//! on Windows CI for the whole release before anyone looked. stdout here
//! is protocol, and a consumer diffing one machine's report against
//! another's must not have to know which operating system produced it.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

const BINARY: &str = env!("CARGO_BIN_EXE_ips-le");
const VALUE: &str = "203.0.113.45";
static COUNTER: AtomicUsize = AtomicUsize::new(0);

struct Tree {
    root: PathBuf,
}

impl Tree {
    fn new(name: &str) -> Self {
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "ips-le-platform-{name}-{}-{unique}",
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
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

/// The binary, with the environment named rather than inherited: `Some`
/// sets the variable, `None` removes it.
fn run_with(args: &[&str], environment: &[(&str, Option<&str>)]) -> Run {
    let mut command = Command::new(BINARY);
    command.args(args).stdin(Stdio::null());
    for (name, value) in environment {
        match value {
            Some(value) => command.env(name, value),
            None => command.env_remove(name),
        };
    }
    let output = command.output().expect("the binary runs");
    Run {
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn run(args: &[&str]) -> Run {
    run_with(args, &[])
}

fn reports(run: &Run) -> Vec<serde_json::Value> {
    run.stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("stdout carries only JSON"))
        .collect()
}

fn files(reports: &[serde_json::Value]) -> Vec<String> {
    reports
        .iter()
        .filter_map(|report| report["file"].as_str().map(str::to_string))
        .collect()
}

fn skipped(case: &str, why: &str) {
    eprintln!("SKIPPED {case}: {why}");
}

/// **Every path in the report uses `/`.** A report produced on Windows
/// and one produced on Linux describe the same tree, and a consumer that
/// splits a path, or diffs the two, must not have to know which machine
/// wrote it.
#[test]
fn every_reported_path_uses_one_separator_on_every_platform() {
    let tree = Tree::new("separators");
    tree.write("infra/edge/hosts.env", &format!("BIND_IP={VALUE}\n"));
    tree.write("top.log", &format!("client_ip={VALUE}\n"));

    let run = run(&[&tree.path().to_string_lossy()]);
    assert_eq!(run.code, Some(0), "stderr: {}", run.stderr);
    let reported = files(&reports(&run));
    assert_eq!(reported.len(), 2, "{reported:?}");
    for file in &reported {
        assert!(!file.contains('\\'), "a backslash in a report path: {file}");
    }
    assert!(
        reported
            .iter()
            .any(|file| file.ends_with("infra/edge/hosts.env")),
        "{reported:?}"
    );

    // The human projection on stderr is the same paths, so it inherits
    // the same rule rather than growing its own spelling.
    assert!(
        !run.stderr.contains('\\'),
        "a backslash on stderr: {}",
        run.stderr
    );
}

/// **`TZ` independence.** Nothing here reads a clock — the report has no
/// timestamp and classification is arithmetic over the bits — so the
/// answer cannot depend on the time zone. Windows ignores the variable
/// entirely, so a suite that quietly depended on it would be red there
/// and nowhere else; this asserts it byte for byte rather than assuming
/// it. The CI job runs the whole suite twice, TZ set and unset, and
/// diffs the test names and outcomes line for line.
#[test]
fn the_answer_does_not_depend_on_the_time_zone() {
    let tree = Tree::new("timezone");
    // A log line full of timestamps: the input most likely to grow a
    // clock-dependent reading if one ever crept in.
    tree.write(
        "access.log",
        &format!("ts=2026-08-12T23:59:59Z client_ip={VALUE} took=1.25ms\n"),
    );
    tree.write("app.yaml", "peer: 2001:0db8::0001\n");
    let root = tree.path().to_string_lossy().into_owned();
    let args = [root.as_str()];

    let utc = run_with(&args, &[("TZ", Some("UTC"))]);
    let unset = run_with(&args, &[("TZ", None)]);
    // A zone a day ahead of UTC: if anything here formatted a local
    // date, this is the run that would differ.
    let far = run_with(&args, &[("TZ", Some("Pacific/Kiritimati"))]);

    assert_eq!(utc.stdout, unset.stdout, "TZ unset changed the report");
    assert_eq!(utc.stdout, far.stdout, "the report moved with the clock");
    assert_eq!(utc.stderr, unset.stderr, "TZ unset changed the summary");
    assert_eq!(utc.stderr, far.stderr, "the summary moved with the clock");
    assert_eq!(
        (utc.code, unset.code, far.code),
        (Some(0), Some(0), Some(0))
    );
}

/// `Hosts.env` and `hosts.env` are one file on macOS and Windows and two
/// on Linux. Either answer is correct; reporting one file **twice** is
/// not, and neither is a walk that disagrees with the filesystem about
/// how many there are.
#[test]
fn a_case_folding_filesystem_reports_each_file_once() {
    let tree = Tree::new("case-fold");
    tree.write("HOSTS.ENV", &format!("BIND_IP={VALUE}\n"));
    tree.write("hosts.env", &format!("BIND_IP={VALUE}\n"));

    let on_disk = std::fs::read_dir(tree.path())
        .expect("the tree is readable")
        .count();
    assert!(
        (1..=2).contains(&on_disk),
        "the filesystem folded case in some third way: {on_disk} entries"
    );
    if on_disk == 1 {
        skipped(
            "case-fold/two-files",
            "this filesystem folds case, so the two names are one file",
        );
    }

    let run = run(&[&tree.path().to_string_lossy()]);
    assert_eq!(run.code, Some(0), "stderr: {}", run.stderr);
    let reported = files(&reports(&run));
    assert_eq!(
        reported.len(),
        on_disk,
        "the walk reported {} lines for {on_disk} files: {reported:?}",
        reported.len()
    );
    let mut unique = reported.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), reported.len(), "a file was reported twice");

    // The format is resolved from the name, and the name folds too:
    // `.ENV` must reach the dotenv reader, or the key path silently
    // disappears on one platform.
    for report in reports(&run) {
        assert_eq!(report["format"], "env", "{report}");
        assert_eq!(report["addresses"][0]["key"], "BIND_IP", "{report}");
    }
}

/// `CON`, `PRN`, `AUX`, `NUL` and `COM1` are device names on Windows and
/// ordinary filenames everywhere else. **The creation is what is allowed
/// to fail**, not the walk: the test never asserts they exist.
#[test]
fn reserved_windows_names_do_not_break_the_walk() {
    let tree = Tree::new("reserved");
    tree.write("ordinary.log", &format!("client_ip={VALUE}\n"));

    let mut created = Vec::new();
    for name in ["CON", "PRN", "AUX", "NUL", "COM1"] {
        let target = tree.path().join(format!("{name}.log"));
        match std::fs::write(&target, format!("client_ip={VALUE}\n")) {
            Ok(()) => created.push(format!("{name}.log")),
            Err(error) => skipped(
                &format!("reserved-names/{name}"),
                &format!("this platform refuses the name ({error})"),
            ),
        }
    }

    let run = run(&[&tree.path().to_string_lossy()]);
    assert_eq!(
        run.code,
        Some(0),
        "the walk did not survive a reserved name\nstderr: {}",
        run.stderr
    );
    let reported = files(&reports(&run));
    assert!(
        reported.iter().any(|file| file.ends_with("ordinary.log")),
        "{reported:?}"
    );
    for name in created {
        assert!(
            reported.iter().any(|file| file.ends_with(&name)),
            "{name} was created and then vanished from the report: {reported:?}"
        );
    }
}

/// A log written on Windows and one written on Linux hold the same
/// addresses at the same positions. The `\r` is not part of the line, so
/// it never reaches a key path and never moves a column — and a key with
/// an invisible carriage return on the end of it is a key path that
/// silently matches nothing downstream.
#[test]
fn a_crlf_log_reads_exactly_like_an_lf_one() {
    let tree = Tree::new("line-endings");
    let body = format!("first line\nclient_ip={VALUE} status=200\npeer=2001:0db8::0001\n");
    tree.write("unix.log", &body);
    tree.write("windows.log", &body.replace('\n', "\r\n"));

    let run = run(&[&tree.path().to_string_lossy()]);
    assert_eq!(run.code, Some(0), "stderr: {}", run.stderr);
    let reports = reports(&run);
    let findings = |name: &str| -> serde_json::Value {
        reports
            .iter()
            .find(|report| {
                report["file"]
                    .as_str()
                    .is_some_and(|file| file.ends_with(name))
            })
            .unwrap_or_else(|| panic!("{name} has no report line"))["addresses"]
            .clone()
    };
    assert_eq!(
        findings("unix.log"),
        findings("windows.log"),
        "a carriage return changed the answer"
    );
    assert_eq!(findings("unix.log")[0]["key"], "client_ip");
    assert_eq!(findings("unix.log")[0]["line"], 2);
}

/// **Assert the exit code, never the write.** A child that refuses
/// before draining stdin closes the pipe under the parent's feet; a test
/// that asserted the write succeeded was red on one platform and green
/// on the others in a sibling, for reasons that had nothing to do with
/// the code.
#[test]
fn a_child_that_refuses_early_does_not_fail_on_the_write() {
    let mut child = Command::new(BINARY)
        .arg("--not-a-flag")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary runs");

    // Deliberately more than a pipe buffer, and deliberately unchecked.
    if let Some(stdin) = child.stdin.as_mut() {
        let _ = stdin.write_all(&vec![b'x'; 1024 * 1024]);
        let _ = stdin.flush();
    }
    drop(child.stdin.take());

    let output = child.wait_with_output().expect("the child finishes");
    assert_eq!(
        output.status.code(),
        Some(2),
        "a malformed question is exit 2 whatever happened to stdin"
    );
    assert!(output.stdout.is_empty(), "a refusal wrote to stdout");
}

/// `--stdin` reads one document to end of stream. Closed with nothing
/// written is an empty document — "none found", which is an answer and
/// not a failure — and the report still names `<stdin>` rather than a
/// path that does not exist.
#[test]
fn a_document_from_stdin_is_read_and_an_empty_one_is_not_an_error() {
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
        .write_all(format!("client_ip={VALUE} status=200\n").as_bytes())
        .expect("writes");
    let output = child.wait_with_output().expect("the child finishes");
    assert_eq!(output.status.code(), Some(0));
    let report: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&output.stdout).trim())
            .expect("stdout carries JSON");
    assert_eq!(report["file"], "<stdin>");
    assert_eq!(report["addresses"][0]["normalized"], VALUE);

    let mut child = Command::new(BINARY)
        .args(["--stdin", "--format", "log"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary runs");
    drop(child.stdin.take());
    let output = child.wait_with_output().expect("the child finishes");
    assert_eq!(
        output.status.code(),
        Some(1),
        "an empty document is not an error"
    );
}

/// The MCP server reads stdin to end of stream. Closing it immediately
/// is a client that went away, and the answer is a clean exit rather
/// than a hang or a non-zero code nobody can act on.
#[test]
fn the_mcp_server_exits_cleanly_when_stdin_closes_immediately() {
    let mut child = Command::new(BINARY)
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary runs");
    drop(child.stdin.take());

    let output = child.wait_with_output().expect("the child finishes");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout was {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
}
