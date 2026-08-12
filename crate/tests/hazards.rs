//! Documents and filesystems that break tools, run against the **built
//! binary**.
//!
//! Not a fixture directory: Windows cannot check in a FIFO, a symlink
//! loop or a permission-denied file, so every tree here is built at
//! runtime and each case the platform cannot express says plainly, by
//! name, that it did not run. **A skip is never reported as a pass.**
//!
//! Every case asserts the same floor first: the process does not panic,
//! does not hang, and exits 0, 1 or 2 — never on a signal.
//!
//! Each content hazard carries an address the crate should find, so "no
//! crash" is never mistaken for "no answer". The three outcomes a file
//! can have here are all real and all different, and a case names which
//! one it expects:
//!
//! - **read** — a report line, and the addresses in it;
//! - **unexamined** — a report line carrying a `skipped` diagnostic,
//!   because the bytes were not UTF-8;
//! - **binary** — *no* report line at all, counted on stderr, because a
//!   NUL byte in the first 8 KiB means the file was never a text
//!   candidate.

use std::fmt::Write as _;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const BINARY: &str = env!("CARGO_BIN_EXE_ips-le");

/// The address every content hazard hides. Documentation range on
/// purpose: distinctive enough that finding it in stdout is proof the
/// document was read rather than merely opened, and unmistakable for a
/// path or a version if it ever turns up in a diff.
const VALUE: &str = "203.0.113.45";

/// Generous enough for a shared runner reading a three-megabyte line,
/// tight enough that a blocking read on a FIFO is a failure rather than
/// a coffee break.
const LIMIT: Duration = Duration::from_secs(120);

static COUNTER: AtomicUsize = AtomicUsize::new(0);

struct Tree {
    root: PathBuf,
}

impl Tree {
    fn new(name: &str) -> Self {
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "ips-le-hazard-{name}-{}-{unique}",
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

/// Runs the binary and **fails rather than blocks**. A hang is one of
/// the two failure modes this file exists to catch — a FIFO with no
/// writer is one `read` away from an eternal CI job — so the child is
/// killed at the deadline and the case is named.
fn run(case: &str, args: &[&str]) -> Run {
    let mut child = Command::new(BINARY)
        .args(args)
        // Never inherit the terminal: a child waiting on a keyboard that
        // is not there is a hang with an innocent explanation.
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary runs");

    // Drained on threads: a child writing more than a pipe buffer would
    // deadlock against a parent that waits before reading, and the
    // reports here run to megabytes.
    let mut out = child.stdout.take().expect("stdout");
    let mut err = child.stderr.take().expect("stderr");
    let out = std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = out.read_to_end(&mut buffer);
        buffer
    });
    let err = std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = err.read_to_end(&mut buffer);
        buffer
    });

    let deadline = Instant::now() + LIMIT;
    let status = loop {
        match child.try_wait().expect("the child is waitable") {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("{case}: hung for {LIMIT:?} on {args:?}");
            }
            None => std::thread::sleep(Duration::from_millis(10)),
        }
    };

    // `None` means the process died on a signal — the SIGSEGV/SIGABRT
    // class, which no input may produce.
    let code = status.code().unwrap_or_else(|| {
        panic!("{case}: died on a signal rather than exiting ({status:?}) on {args:?}")
    });
    assert!(
        (0..=2).contains(&code),
        "{case}: exit {code} is outside grep's 0/1/2 on {args:?}"
    );
    Run {
        code,
        stdout: String::from_utf8_lossy(&out.join().expect("stdout thread")).into_owned(),
        stderr: String::from_utf8_lossy(&err.join().expect("stderr thread")).into_owned(),
    }
}

/// Every line of stdout, parsed. Doubles as the assertion that stdout is
/// JSON Lines and nothing else — a stray human message there would fail
/// to parse.
fn reports(run: &Run) -> Vec<serde_json::Value> {
    run.stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("stdout carries only JSON"))
        .collect()
}

fn report_for<'a>(reports: &'a [serde_json::Value], name: &str) -> Option<&'a serde_json::Value> {
    reports.iter().find(|report| {
        report["file"]
            .as_str()
            .is_some_and(|file| file.ends_with(name))
    })
}

fn named(reports: &[serde_json::Value]) -> Vec<&str> {
    reports
        .iter()
        .filter_map(|report| report["file"].as_str())
        .collect()
}

fn addresses(report: &serde_json::Value) -> u64 {
    report["summary"]["addresses"].as_u64().unwrap_or_default()
}

fn was_skipped(report: &serde_json::Value) -> bool {
    report["diagnostics"]
        .as_array()
        .is_some_and(|list| list.iter().any(|entry| entry["code"] == "skipped"))
}

/// A case the platform cannot express. Named on stderr so a green run
/// still says what it did not check — a silent skip is a lie.
fn skipped(case: &str, why: &str) {
    eprintln!("SKIPPED {case}: {why}");
}

/// UTF-16LE bytes with a byte-order mark: what Notepad writes when asked
/// for "Unicode", and what a PowerShell redirect produces.
fn utf16le(text: &str) -> Vec<u8> {
    let mut bytes = vec![0xff, 0xfe];
    for unit in text.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes
}

// ---------------------------------------------------------------- content

/// What a file is allowed to come back as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// A report line, and this many addresses named in it.
    Read(u64),
    /// A report line carrying a `skipped` diagnostic: the bytes were not
    /// UTF-8, so the file was named rather than silently dropped.
    Unexamined,
    /// No report line at all. A NUL byte in the first 8 KiB is
    /// ripgrep's own binary heuristic, and a binary file was never a
    /// text candidate — it is counted on stderr instead.
    Binary,
}

/// Every content hazard, and the outcome each one must have.
///
/// They are here rather than in a unit test because the shapes are
/// byte-level and only exist on the way in from the filesystem: a
/// byte-order mark, a lone CR, a UTF-16 encoding, bytes that are not
/// UTF-8 at all.
fn content_hazards() -> Vec<(&'static str, Vec<u8>, Outcome)> {
    let line = format!("client_ip={VALUE} status=200\n");

    let mut many_lines = String::with_capacity(1_400_000);
    for index in 0..100_000 {
        let _ = writeln!(many_lines, "ts=2026-08-12 line {index} status=200");
    }
    many_lines.push_str(&line);

    let mut long_line = String::with_capacity(1_100_000);
    long_line.push_str("note=");
    long_line.push_str(&"x".repeat(1024 * 1024));
    long_line.push(' ');
    long_line.push_str(&line);

    vec![
        ("plain.log", line.clone().into_bytes(), Outcome::Read(1)),
        // Three invisible bytes Notepad, Excel and a PowerShell redirect
        // all add, and that no editor shows.
        (
            "bom.log",
            format!("\u{feff}{line}").into_bytes(),
            Outcome::Read(1),
        ),
        // A log written on Windows. The `\r` must not reach the key or
        // the address, and must not move the column.
        (
            "crlf.log",
            format!("first line\r\nclient_ip={VALUE} status=200\r\n").into_bytes(),
            Outcome::Read(1),
        ),
        // A lone CR is not a line ending here, so the whole file is one
        // line. Pinned rather than improved: the address is still found.
        (
            "lone-cr.log",
            format!("first line\r{line}").into_bytes(),
            Outcome::Read(1),
        ),
        // The last line of a log being written to right now has no
        // newline after it, and it is the line a reader most wants.
        (
            "no-trailing-newline.log",
            format!("client_ip={VALUE} status=200").into_bytes(),
            Outcome::Read(1),
        ),
        ("empty.log", Vec::new(), Outcome::Read(0)),
        ("whitespace.log", b"   \n\t\n \n".to_vec(), Outcome::Read(0)),
        // A four-byte character before the address: the column is
        // counted in UTF-16 units, and the offsets must survive it.
        (
            "astral-before.log",
            format!("\u{1f3af} {line}").into_bytes(),
            Outcome::Read(1),
        ),
        (
            "one-megabyte-line.log",
            long_line.into_bytes(),
            Outcome::Read(1),
        ),
        (
            "hundred-thousand-lines.log",
            many_lines.into_bytes(),
            Outcome::Read(1),
        ),
        // Not UTF-8 by any reading: named on stderr, carried in the
        // report, never silently absent from the audit.
        (
            "invalid-utf8.log",
            [b"client_ip=\xff\xfe ".to_vec(), VALUE.as_bytes().to_vec()].concat(),
            Outcome::Unexamined,
        ),
        // A UTF-16 log file is mostly NUL bytes, so it is binary by the
        // same rule a PNG is — it never reaches the UTF-8 decision at
        // all, and gets no report line.
        ("utf16le.log", utf16le(&line), Outcome::Binary),
        (
            "logo.png",
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR".to_vec(),
            Outcome::Binary,
        ),
    ]
}

/// One tree, one run of the binary, and each file held to the outcome
/// its case names.
#[test]
fn every_content_hazard_is_read_named_or_counted() {
    let tree = Tree::new("content");
    let cases = content_hazards();

    for (name, bytes, _) in &cases {
        tree.write_bytes(name, bytes);
    }

    let run = run("content", &[&tree.path().to_string_lossy()]);
    assert_eq!(run.code, 0, "addresses were found\nstderr: {}", run.stderr);
    let reports = reports(&run);

    for (name, _, outcome) in &cases {
        let report = report_for(&reports, name);
        match outcome {
            Outcome::Binary => assert!(
                report.is_none(),
                "{name}: a binary file produced a report line: {report:?}"
            ),
            Outcome::Unexamined => {
                let report = report.unwrap_or_else(|| {
                    panic!("{name} vanished from the audit: {:?}", named(&reports))
                });
                assert!(was_skipped(report), "{name}: {report}");
                assert_eq!(addresses(report), 0, "{name}: {report}");
            }
            Outcome::Read(expected) => {
                let report = report.unwrap_or_else(|| {
                    panic!("{name} vanished from the audit: {:?}", named(&reports))
                });
                assert!(!was_skipped(report), "{name}: {report}");
                assert_eq!(addresses(report), *expected, "{name}: {report}");
            }
        }
    }

    let binary = cases
        .iter()
        .filter(|(_, _, outcome)| *outcome == Outcome::Binary)
        .count();
    assert!(
        run.stderr
            .contains(&format!("{binary} binary files skipped")),
        "the binary files were not counted on stderr: {}",
        run.stderr
    );
}

/// A byte-order mark is three bytes no editor shows. If it reached the
/// scanner, every position on the first line of a file written by
/// anything on Windows would be off by three against the editor the
/// reader has open.
#[test]
fn a_byte_order_mark_moves_no_position() {
    let tree = Tree::new("bom");
    let line = format!("client_ip={VALUE} status=200\n");
    tree.write("plain.log", &line);
    tree.write("marked.log", &format!("\u{feff}{line}"));

    let run = run("bom", &[&tree.path().to_string_lossy()]);
    let reports = reports(&run);
    let plain = report_for(&reports, "plain.log").expect("plain.log");
    let marked = report_for(&reports, "marked.log").expect("marked.log");
    assert_eq!(
        marked["addresses"][0]["column"], plain["addresses"][0]["column"],
        "a byte-order mark moved the reported column"
    );
    assert_eq!(
        marked["addresses"][0]["line"],
        plain["addresses"][0]["line"]
    );
    assert_eq!(marked["addresses"][0]["key"], plain["addresses"][0]["key"]);
}

/// The document a line-oriented key reader cannot answer for, which is
/// why JSON is the one format here with a parser. Several megabytes on
/// one line, and every finding still carries the key it sits under.
#[test]
fn a_multi_megabyte_minified_json_document_is_read_with_its_keys() {
    const HOSTS: usize = 5_000;

    let tree = Tree::new("minified");
    let mut document = String::with_capacity(3_000_000);
    document.push('{');
    for index in 0..HOSTS {
        // Padding, so the document is measured in megabytes rather than
        // in addresses: a minified bundle is mostly not the thing you
        // are looking for.
        let _ = write!(
            document,
            "\"pad{index:05}\":\"{}\",\"host{index:05}\":{{\"ip\":\"10.{}.{}.{}\"}},",
            "y".repeat(500),
            index / 65536,
            (index / 256) % 256,
            index % 256,
        );
    }
    let _ = write!(document, "\"last\":\"{VALUE}\"}}");
    assert!(
        document.len() > 2 * 1024 * 1024,
        "the document must be several megabytes, not {}",
        document.len()
    );
    let file = tree.write("bundle.json", &document);

    let started = Instant::now();
    let run = run("minified", &[&file.to_string_lossy()]);
    eprintln!(
        "hazards: {} bytes of minified JSON in {:?}",
        document.len(),
        started.elapsed()
    );
    assert_eq!(run.code, 0, "{}", run.stderr);

    let reports = reports(&run);
    let report = report_for(&reports, "bundle.json").expect("bundle.json");
    assert_eq!(report["format"], "json");
    assert_eq!(addresses(report), HOSTS as u64 + 1);
    assert_eq!(
        report["addresses"][0]["key"], "host00000.ip",
        "a minified document lost its key paths: {}",
        report["addresses"][0]
    );
}

// ------------------------------------------------------------- filesystem

/// Names a filesystem accepts and a walker can trip over, including a
/// directory named like a document — the walk must descend it rather
/// than try to read it.
#[test]
fn awkward_names_are_walked() {
    let tree = Tree::new("names");
    let line = format!("client_ip={VALUE}\n");
    let mut written = Vec::new();
    for name in [
        "with spaces.log",
        "na\u{ef}ve-\u{434}\u{43e}\u{43a}.log",
        "emoji-\u{1f3af}.log",
        "trailing.dots..log",
    ] {
        if std::fs::write(tree.path().join(name), &line).is_err() {
            skipped("awkward-names", name);
            continue;
        }
        written.push(name);
    }
    tree.write("app.json/inside.log", &line);
    assert!(!written.is_empty(), "this filesystem refused every name");

    let run = run("names", &[&tree.path().to_string_lossy()]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    let reports = reports(&run);
    for name in written {
        let report = report_for(&reports, name).unwrap_or_else(|| panic!("{name}"));
        assert_eq!(addresses(report), 1, "{name}");
    }
    assert_eq!(
        addresses(report_for(&reports, "inside.log").expect("inside")),
        1
    );
    assert!(
        report_for(&reports, "app.json").is_none()
            || report_for(&reports, "app.json/inside.log").is_some(),
        "a directory was read as a document: {:?}",
        named(&reports)
    );
}

/// Where Windows differs: `MAX_PATH` is 260 characters unless long paths
/// are enabled, so the creation itself is the platform's answer. What is
/// asserted is that the walk survives whichever happened, and that the
/// file beside it is still audited.
#[test]
fn a_path_over_260_characters_is_read_or_skipped_by_name() {
    let tree = Tree::new("long-path");
    let line = format!("client_ip={VALUE}\n");
    tree.write("shallow.log", &line);

    let mut deep = tree.path().to_path_buf();
    for _ in 0..9 {
        deep.push("a-directory-with-a-long-name");
    }
    let created = std::fs::create_dir_all(&deep)
        .and_then(|()| std::fs::write(deep.join("deep.log"), &line))
        .is_ok();
    if !created {
        skipped(
            "long-path",
            "this filesystem refused a path over 260 characters",
        );
    }

    let run = run("long-path", &[&tree.path().to_string_lossy()]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    let reports = reports(&run);
    assert_eq!(
        addresses(report_for(&reports, "shallow.log").expect("shallow")),
        1
    );
    if created {
        assert_eq!(
            addresses(report_for(&reports, "deep.log").expect("deep")),
            1
        );
    }
}

/// The hang this file exists for. A FIFO with no writer blocks a `read`
/// forever, and the walk reads every regular file it reaches — so the
/// answer has to be that a named pipe is never a regular file.
#[cfg(unix)]
#[test]
fn a_fifo_never_blocks_the_walk() {
    let tree = Tree::new("fifo");
    tree.write("real.log", &format!("client_ip={VALUE}\n"));
    let fifo = tree.path().join("pipe.log");
    // Shelled out rather than called through libc: `unsafe` is forbidden
    // crate-wide and a test is not an exemption.
    let made = Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .is_ok_and(|status| status.success());
    if !made {
        skipped("fifo", "mkfifo is not available on this runner");
        return;
    }

    let walked = run("fifo-tree", &[&tree.path().to_string_lossy()]);
    assert_eq!(walked.code, 0, "{}", walked.stderr);
    let reports = reports(&walked);
    assert_eq!(
        addresses(report_for(&reports, "real.log").expect("real")),
        1
    );
    assert!(
        report_for(&reports, "pipe.log").is_none(),
        "a named pipe was read as a document: {:?}",
        named(&reports)
    );

    // Named explicitly, it is not a regular file either — and still
    // must not be opened and waited on.
    let named_directly = run("fifo-named", &[&fifo.to_string_lossy()]);
    assert_eq!(named_directly.code, 1, "{}", named_directly.stderr);
}

#[cfg(not(unix))]
#[test]
fn a_fifo_never_blocks_the_walk() {
    skipped("fifo", "Windows has no FIFO in a directory tree");
}

/// Symlinks are never followed, so a loop is not a loop for this walk.
/// A loop the caller *names* is a path that cannot be resolved, which is
/// a malformed question and exits 2 by name.
#[cfg(unix)]
#[test]
fn a_symlink_loop_is_not_followed_and_never_hangs() {
    let tree = Tree::new("loop");
    tree.write("real.log", &format!("client_ip={VALUE}\n"));
    let first = tree.path().join("loop-a.log");
    let second = tree.path().join("loop-b.log");
    if std::os::unix::fs::symlink(&second, &first).is_err()
        || std::os::unix::fs::symlink(&first, &second).is_err()
    {
        skipped("symlink-loop", "this platform refused to create a symlink");
        return;
    }
    // A link to the tree's own root: the shape that turns a walk into an
    // infinite descent when links are followed.
    let _ = std::os::unix::fs::symlink(tree.path(), tree.path().join("self"));

    let walked = run("loop-tree", &[&tree.path().to_string_lossy()]);
    assert_eq!(
        walked.code, 0,
        "a symlink loop ended the run: {}",
        walked.stderr
    );
    let reports = reports(&walked);
    assert_eq!(
        addresses(report_for(&reports, "real.log").expect("real")),
        1
    );
    assert!(
        report_for(&reports, "loop-a.log").is_none(),
        "a symlink was walked: {:?}",
        named(&reports)
    );

    let by_name = run("loop-named", &[&first.to_string_lossy()]);
    assert_eq!(by_name.code, 2, "{}", by_name.stderr);
    assert!(
        by_name.stderr.contains("loop-a.log"),
        "the refusal does not name the path: {}",
        by_name.stderr
    );
    assert!(
        by_name.stdout.is_empty(),
        "a refusal wrote to the protocol stream"
    );
}

#[cfg(not(unix))]
#[test]
fn a_symlink_loop_is_not_followed_and_never_hangs() {
    skipped(
        "symlink-loop",
        "creating one needs Developer Mode or elevation on Windows",
    );
}

/// **Exit 2 is for a malformed question, never for a file the
/// filesystem refused.** One locked directory used to end the whole run
/// with an empty report, which deleted the audit of everything readable
/// beside it. It is a report line now, and `--strict` is how a pipeline
/// asks for zero tolerance.
#[cfg(unix)]
#[test]
fn permission_denied_is_named_carried_and_never_ends_the_run() {
    use std::os::unix::fs::PermissionsExt as _;

    let tree = Tree::new("denied");
    tree.write("readable.log", &format!("client_ip={VALUE}\n"));
    let file = tree.write("denied.log", "client_ip=10.0.0.1\n");
    let directory = tree.path().join("locked");
    std::fs::create_dir_all(&directory).expect("a directory");
    std::fs::write(directory.join("inside.log"), "client_ip=10.0.0.2\n").expect("a file");
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o000)).expect("chmod");
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o000)).expect("chmod");

    let readable_anyway = std::fs::read(&file).is_ok();
    let lenient = run("denied", &[&tree.path().to_string_lossy()]);
    let strict = run(
        "denied-strict",
        &["--strict", &tree.path().to_string_lossy()],
    );

    // Restored before asserting, or a failure leaves a directory the
    // cleanup cannot remove.
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).expect("chmod");
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).expect("chmod");

    if readable_anyway {
        skipped(
            "permission-denied",
            "this runner reads a mode-000 path anyway (root)",
        );
        return;
    }

    assert_eq!(
        lenient.code, 0,
        "an unreadable path ended the run\nstderr: {}",
        lenient.stderr
    );
    let reports = reports(&lenient);
    assert_eq!(
        addresses(report_for(&reports, "readable.log").expect("readable")),
        1,
        "the readable half of the tree was lost"
    );
    let refused = report_for(&reports, "denied.log").expect("the denied file has a report line");
    assert!(was_skipped(refused), "{refused}");
    let locked = report_for(&reports, "locked").expect("the locked directory has a report line");
    assert!(was_skipped(locked), "{locked}");
    assert!(
        lenient.stderr.contains("denied.log") && lenient.stderr.contains("locked"),
        "a path that could not be read was not named on stderr: {}",
        lenient.stderr
    );

    assert_eq!(
        strict.code, 2,
        "--strict ignored a path that could not be examined\nstderr: {}",
        strict.stderr
    );
}

#[cfg(not(unix))]
#[test]
fn permission_denied_is_named_carried_and_never_ends_the_run() {
    skipped(
        "permission-denied",
        "Windows ACLs are not chmod; the unix case covers the read failure",
    );
}

/// The only two ways to reach exit 2 without `--strict`: a flag that is
/// not one, and a path that is not there. Both are the *question* being
/// malformed, and neither writes to the protocol stream.
#[test]
fn a_malformed_question_is_the_only_other_exit_two() {
    let tree = Tree::new("exit-two");
    let missing = tree
        .path()
        .join("not-here.log")
        .to_string_lossy()
        .into_owned();
    for args in [
        vec!["--no-such-flag", "."],
        vec![missing.as_str()],
        vec!["--kind", "ipv5", "."],
        vec!["--format"],
        vec![],
    ] {
        let refused = run("exit-two", &args);
        assert_eq!(refused.code, 2, "{args:?}: {}", refused.stderr);
        assert!(
            refused.stdout.is_empty(),
            "{args:?} wrote to the protocol stream"
        );
        assert!(
            refused.stderr.starts_with("ips-le:"),
            "{args:?}: {}",
            refused.stderr
        );
    }
}
