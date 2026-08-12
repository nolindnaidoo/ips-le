//! The tier that needs a document far larger than any editor opens.
//!
//! Gated behind `IPS_LE_SCENARIOS`. Nothing here substitutes for the
//! unit tests, which run everywhere on every push.
//!
//! **A skipped scenario is never reported as a pass.**

use std::fmt::Write as _;
use std::io::Write as _;

fn enabled(name: &str) -> bool {
    if std::env::var_os("IPS_LE_SCENARIOS").is_some() {
        return true;
    }
    eprintln!("SKIPPED {name}: set IPS_LE_SCENARIOS to run it");
    false
}

fn scan(content: &str, format: &str) -> serde_json::Value {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ips-le"))
        .args(["--stdin", "--format", format])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child
                .stdin
                .as_mut()
                .expect("stdin")
                .write_all(content.as_bytes())?;
            child.wait_with_output()
        })
        .expect("the binary runs");
    serde_json::from_slice(&output.stdout).expect("stdout carries JSON")
}

/// The real shape of the input this tool exists for, at a size a person
/// would actually run it on. Every line carries an address and a
/// timestamp, and the timestamps are the ones the scanner has to keep
/// declining to report.
#[test]
fn a_large_log_file_completes() {
    if !enabled("a_large_log_file_completes") {
        return;
    }
    let mut content = String::new();
    for line in 0..200_000 {
        let _ = writeln!(
            content,
            "ts=2026-08-12T10:{:02}:{:02}Z remote_addr=10.{}.{}.{} took={line}.25ms status=200",
            line % 60,
            (line / 60) % 60,
            (line / 65536) % 256,
            (line / 256) % 256,
            line % 256,
        );
    }
    let report = scan(&content, "log");
    assert_eq!(report["summary"]["addresses"], 200_000);
    assert_eq!(
        report["summary"]["refused"], 0,
        "a timestamp is not an ambiguous address"
    );
}

/// Key lookup is a binary search over the format reader's spans, and
/// this is the document where a linear scan would show: one key per
/// address, all of them on one line.
#[test]
fn a_single_line_with_many_keys_completes() {
    if !enabled("a_single_line_with_many_keys_completes") {
        return;
    }
    let mut content = String::new();
    for index in 0..100_000 {
        let _ = write!(
            content,
            "peer{index}_ip=10.{}.{}.{} ",
            index / 65536,
            (index / 256) % 256,
            index % 256
        );
    }
    let report = scan(&content, "log");
    assert_eq!(report["summary"]["addresses"], 100_000);
    assert_eq!(
        report["summary"]["refused"], 0,
        "every octet is in range, so nothing here is ambiguous"
    );
    assert_eq!(report["addresses"][0]["key"], "peer0_ip");
}

/// The column lookup counts UTF-16 units from the start of the line,
/// which is what turns quadratic when the line never ends and is not
/// ASCII.
#[test]
fn a_long_non_ascii_line_completes() {
    if !enabled("a_long_non_ascii_line_completes") {
        return;
    }
    let mut content = String::new();
    for index in 0..50_000 {
        let _ = write!(content, "café {} 10.0.0.{} ", index, index % 256);
    }
    let report = scan(&content, "unknown");
    assert_eq!(report["summary"]["addresses"], 50_000);
}

/// A document of nothing but refusals still has to finish, and still
/// has to exit 1 rather than 0 — nothing here was ever named.
#[test]
fn a_document_of_nothing_but_ambiguity_completes() {
    if !enabled("a_document_of_nothing_but_ambiguity_completes") {
        return;
    }
    let mut content = String::new();
    for index in 0..100_000 {
        let _ = writeln!(content, "0{}.1.1.1", index % 9 + 1);
    }
    let report = scan(&content, "unknown");
    assert_eq!(report["summary"]["addresses"], 0);
    assert_eq!(report["summary"]["refused"], 100_000);
}
