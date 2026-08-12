//! Does this crate open what it claims to open, and say everything it
//! claims to say?
//!
//! Four questions, all mechanical, all previously answered by hand:
//!
//! 1. **Every kind, class and refusal reason is reachable from a real
//!    fixture** — through the walk, a format reader and the built
//!    binary, not through a unit call on `policy::read`. A class nothing
//!    reaches is a class this tool claims and has never produced.
//! 2. **Nothing produced is outside those lists.** A value added to an
//!    enum and not to the vocabulary would otherwise appear in a report
//!    that documents nine classes and ships ten.
//! 3. **Every advertised format opens a real file** and reports itself
//!    by name, plus the fallback — a format offered by `--format` and
//!    the tool schema that no file ever resolves to is a promise nobody
//!    has checked.
//! 4. **The vocabulary and the documentation agree.** Every name here is
//!    in SPEC.md and, where the flag offers it, in `--help`.
//!
//! Ubuntu only: nothing here is platform-dependent, and running it three
//! times would only buy three chances to trip over a case-folding
//! filesystem while asserting nothing new.
//!
//! **The marker lines at the end are not decoration.** `cargo test
//! <filter>` exits 0 when the filter matches nothing, so a renamed test
//! would pass this job silently; CI greps for the markers instead.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

const BINARY: &str = env!("CARGO_BIN_EXE_ips-le");
const CRATE: &str = env!("CARGO_MANIFEST_DIR");
const SPEC: &str = include_str!("../SPEC.md");
const CORPUS: &str = include_str!("../fixtures/extraction.json");

/// The vocabulary, repeated here because an integration test cannot see
/// a `pub(crate)` constant. Held equal to `Kind::ALL`, `Class::ALL` and
/// the `Reason` enum by the assertions below: every name must be
/// produced by a fixture, and nothing produced may be missing from these
/// lists.
const KINDS: [&str; 4] = ["ipv4", "ipv6", "cidr", "mac"];

const CLASSES: [&str; 10] = [
    "loopback",
    "private",
    "link-local",
    "cgnat",
    "multicast",
    "broadcast",
    "reserved",
    "documentation",
    "unique-local",
    "global",
];

const REASONS: [&str; 6] = [
    "octal_hazard",
    "ambiguous_version",
    "malformed_address",
    "prefix_out_of_range",
    "mac_ambiguous",
    "integer_form",
];

/// Every format the crate offers, and one filename that must resolve to
/// it. `unknown` is in the list on purpose: it is the answer for every
/// file this crate has no reader for, which is most of a real tree, and
/// a fallback nothing exercises is a fallback nobody has run.
const FORMATS: [(&str, &str); 8] = [
    ("json", "config.json"),
    ("yaml", "app.yaml"),
    ("toml", "Cargo.toml"),
    ("ini", "settings.ini"),
    ("env", "hosts.env"),
    ("csv", "inventory.csv"),
    ("log", "access.log.1"),
    ("unknown", "main.tf"),
];

struct Tree {
    root: PathBuf,
}

impl Tree {
    fn new(name: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("ips-le-matrix-{name}-{}", std::process::id()));
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

/// Every report line from one run. `--hidden --no-ignore` so the answer
/// does not depend on a developer's global gitignore.
///
/// 0 or 1, never 2: a document of nothing but ambiguities names no
/// address and exits 1, which is an answer rather than a failure — and
/// it is exactly the document the refusal half of this matrix runs on.
fn scan(target: &Path) -> Vec<serde_json::Value> {
    let output = Command::new(BINARY)
        .args(["--hidden", "--no-ignore"])
        .arg(target)
        .output()
        .expect("the binary runs");
    assert!(
        matches!(output.status.code(), Some(0 | 1)),
        "the scan of {} was refused: {}",
        target.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("stdout carries only JSON"))
        .collect()
}

fn findings(reports: &[serde_json::Value]) -> Vec<serde_json::Value> {
    reports
        .iter()
        .flat_map(|report| report["addresses"].as_array().cloned().unwrap_or_default())
        .collect()
}

/// The `ambiguity` corpus as a document on disk.
///
/// Rendered rather than invented: every line is a case
/// `fixtures/extraction.json` already pins, carrying the key the corpus
/// gives it where the refusal depends on one — `integer_form` fires only
/// under an address key, so it is unreachable from any document that
/// has no keys at all.
fn ambiguity_document() -> String {
    let corpus: serde_json::Value = serde_json::from_str(CORPUS).expect("the corpus is valid JSON");
    let cases = corpus["ambiguity"]
        .as_array()
        .expect("the corpus has an ambiguity section");
    assert!(!cases.is_empty(), "the corpus pins no ambiguities");

    let mut document = String::new();
    for (index, case) in cases.iter().enumerate() {
        let input = case["input"].as_str().expect("an input");
        let key = case["key"].as_str().map_or_else(
            // A key naming neither a version nor an address, so the case
            // is read exactly as the corpus states it.
            || format!("case{index}"),
            str::to_string,
        );
        let _ = writeln!(document, "{key}={input}");
    }
    document
}

/// Every named value of one field across a set of findings.
fn seen(findings: &[serde_json::Value], field: &str) -> BTreeSet<String> {
    findings
        .iter()
        .filter_map(|found| found[field].as_str().map(str::to_string))
        .collect()
}

fn missing<'a>(declared: &[&'a str], seen: &BTreeSet<String>) -> Vec<&'a str> {
    declared
        .iter()
        .filter(|name| !seen.contains(**name))
        .copied()
        .collect()
}

fn undeclared(declared: &[&str], seen: &BTreeSet<String>) -> Vec<String> {
    seen.iter()
        .filter(|name| !declared.contains(&name.as_str()))
        .cloned()
        .collect()
}

#[test]
fn every_kind_class_and_refusal_reason_is_reachable_from_a_real_fixture() {
    let documents = PathBuf::from(CRATE).join("fixtures/documents");
    let tree = Tree::new("ambiguity");
    let ambiguity = tree.write("ambiguity.env", &ambiguity_document());

    let mut found = findings(&scan(&documents));
    found.extend(findings(&scan(&ambiguity)));

    let kinds = seen(&found, "kind");
    let classes = seen(&found, "class");
    let reasons: BTreeSet<String> = found
        .iter()
        .filter_map(|one| one["refused"]["reason"].as_str().map(str::to_string))
        .collect();

    assert!(
        missing(&KINDS, &kinds).is_empty(),
        "no fixture produces these kinds: {:?}",
        missing(&KINDS, &kinds)
    );
    assert!(
        missing(&CLASSES, &classes).is_empty(),
        "no fixture produces these classes: {:?}",
        missing(&CLASSES, &classes)
    );
    assert!(
        missing(&REASONS, &reasons).is_empty(),
        "no fixture produces these refusal reasons: {:?}",
        missing(&REASONS, &reasons)
    );

    // The other direction. A value the code emits and the vocabulary
    // does not list is a report that documents nine classes and ships
    // ten — and the reader has no way to know which.
    assert!(
        undeclared(&KINDS, &kinds).is_empty(),
        "these kinds are produced and undocumented: {:?}",
        undeclared(&KINDS, &kinds)
    );
    assert!(
        undeclared(&CLASSES, &classes).is_empty(),
        "these classes are produced and undocumented: {:?}",
        undeclared(&CLASSES, &classes)
    );
    assert!(
        undeclared(&REASONS, &reasons).is_empty(),
        "these refusal reasons are produced and undocumented: {:?}",
        undeclared(&REASONS, &reasons)
    );

    println!(
        "coverage-matrix: {} kinds, {} classes, {} refusal reasons reachable from the corpus",
        kinds.len(),
        classes.len(),
        reasons.len()
    );
}

/// A format the tool advertises and no filename resolves to is a format
/// nobody has ever run. Every one of them is written as a real file,
/// walked, and asked to name itself.
#[test]
fn every_advertised_format_opens_a_real_file_and_names_itself() {
    let tree = Tree::new("formats");
    // One address per file, spelled the way that format spells a value,
    // so a reader that resolves but reads nothing is a failure rather
    // than a pass.
    let bodies: [(&str, String); 8] = [
        (
            "json",
            "{\"server\":{\"bind_ip\":\"10.0.0.5\"}}\n".to_string(),
        ),
        ("yaml", "server:\n  bind_ip: 10.0.0.5\n".to_string()),
        ("toml", "[server]\nbind_ip = \"10.0.0.5\"\n".to_string()),
        ("ini", "[server]\nbind_ip = 10.0.0.5\n".to_string()),
        ("env", "BIND_IP=10.0.0.5\n".to_string()),
        ("csv", "name,bind_ip\nedge,10.0.0.5\n".to_string()),
        (
            "log",
            "ts=2026-08-12 client_ip=10.0.0.5 status=200\n".to_string(),
        ),
        ("unknown", "cidr_block = \"10.0.0.5\"\n".to_string()),
    ];

    for (format, filename) in FORMATS {
        let body = &bodies
            .iter()
            .find(|(name, _)| *name == format)
            .unwrap_or_else(|| panic!("{format} has no document"))
            .1;
        tree.write(&format!("{format}/{filename}"), body);
    }

    let reports = scan(tree.path());
    for (format, filename) in FORMATS {
        let report = reports
            .iter()
            .find(|report| {
                report["file"]
                    .as_str()
                    .is_some_and(|file| file.ends_with(filename))
            })
            .unwrap_or_else(|| panic!("{filename} was never walked"));
        assert_eq!(
            report["format"], format,
            "{filename} resolved to {} rather than {format}",
            report["format"]
        );
        assert_eq!(
            report["summary"]["addresses"], 1,
            "{filename} was opened as {format} and the address in it was not found: {report}"
        );

        // The whole point of a format here: it decides whether a finding
        // carries a key path, and nothing else.
        let key = &report["addresses"][0]["key"];
        if format == "unknown" {
            assert!(key.is_null(), "the fallback invented a key path: {report}");
            continue;
        }
        assert!(
            key.is_string(),
            "{format} is advertised as a key reader and produced no key: {report}"
        );
    }

    assert_eq!(
        reports.len(),
        FORMATS.len(),
        "the walk reported files nobody wrote: {reports:?}"
    );
    println!(
        "coverage-matrix: {} format readers reachable from a real file",
        FORMATS.len()
    );
}

/// The vocabulary and the documentation are one contract. A class the
/// tool reports and SPEC.md does not name is a value a reader has no way
/// to look up.
#[test]
fn every_name_in_the_vocabulary_is_documented() {
    for name in KINDS.iter().chain(CLASSES.iter()).chain(REASONS.iter()) {
        assert!(SPEC.contains(name), "SPEC.md does not name {name}");
    }
    for (format, _) in FORMATS {
        assert!(
            SPEC.contains(format),
            "SPEC.md does not name the {format} format"
        );
    }

    // `--kind` and `--class` are the two flags whose values are only
    // discoverable from the help text; a name missing there is a filter
    // you can only find by getting it wrong.
    let help = Command::new(BINARY)
        .arg("--help")
        .output()
        .expect("the binary runs");
    let help = String::from_utf8_lossy(&help.stdout);
    for name in KINDS.iter().chain(CLASSES.iter()) {
        assert!(help.contains(name), "--help does not name {name}");
    }
}
