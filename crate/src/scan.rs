//! One file end to end — the only path either surface calls.
//!
//! `cli.rs` and `mcp/` both come through here, so a rule can only be
//! written once. `tests/contracts.rs` asserts the two agree.

use std::path::{Path as StdPath, PathBuf};

use serde::Serialize;

use crate::extract::{self, Class, Found, Kind, resolve_format};
use crate::walk::{self, WalkOptions};

/// The report format version.
///
/// Present from 0.1.0, and its own field rather than a guess from the
/// shape, because everything downstream of this tool is a script that
/// has to know whether it can read what it was handed.
const SCHEMA: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Diagnostic {
    pub(crate) severity: String,
    pub(crate) code: String,
    pub(crate) message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct Summary {
    /// Addresses this tool was willing to name. Refusals are not in
    /// here — that is the whole point of counting them separately.
    pub(crate) addresses: usize,
    pub(crate) refused: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct FileReport {
    pub(crate) schema: u32,
    pub(crate) file: String,
    pub(crate) format: String,
    pub(crate) addresses: Vec<Found>,
    pub(crate) diagnostics: Vec<Diagnostic>,
    pub(crate) summary: Summary,
}

impl FileReport {
    /// Whether this file was not read at all — not text, or not
    /// openable.
    ///
    /// Reported rather than swallowed, because a report that quietly
    /// skipped a file would be claiming coverage it does not have. It
    /// does **not** fail the run on its own: every repository has a PNG
    /// and a zip in it, and exiting 2 on those makes the tool unusable
    /// in CI, which is the one place it is most worth running.
    /// `--strict` is there for a pipeline that wants zero tolerance.
    pub(crate) fn was_skipped(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "skipped")
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ScanOptions {
    /// A format the caller forced, instead of one inferred per file.
    pub(crate) format: Option<&'static str>,
    /// Keep only these kinds. Empty means every kind.
    pub(crate) kinds: Vec<Kind>,
    /// Keep only these classes. Empty means every class.
    pub(crate) classes: Vec<Class>,
}

/// What reading one file produced.
///
/// **A binary file is not a report.** It was never a text candidate —
/// every repository holds a PNG — and reporting it as a file that could
/// not be read made `--strict` exit 2 on any tree containing an image.
/// It is counted instead, so the reader still knows coverage was
/// narrower than the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Scanned {
    Read(Box<FileReport>),
    Binary,
}

impl Scanned {
    pub(crate) fn into_report(self) -> Option<FileReport> {
        match self {
            Self::Read(report) => Some(*report),
            Self::Binary => None,
        }
    }
}

/// Split what a walk produced into the reports and the count of files
/// that were never text. Both surfaces come through here so neither can
/// grow its own idea of what a binary file is.
pub(crate) fn partition(scanned: Vec<Scanned>) -> (Vec<FileReport>, usize) {
    let binary = scanned
        .iter()
        .filter(|one| **one == Scanned::Binary)
        .count();
    let reports = scanned
        .into_iter()
        .filter_map(Scanned::into_report)
        .collect();
    (reports, binary)
}

/// ripgrep's heuristic, and deliberately the same one: a NUL byte in
/// the first 8 KiB means binary.
const BINARY_SNIFF_BYTES: usize = 8192;

fn is_binary(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .take(BINARY_SNIFF_BYTES)
        .any(|byte| *byte == b'\0')
}

/// The path as the report spells it: **separated by `/` on every
/// platform**.
///
/// A report is diffed against one produced on another machine and read
/// by someone who does not have the tree. A sibling in this family
/// shipped `\` on Windows for a whole release, which made every path in
/// a Windows report differ from the same path in a Linux one for no
/// reason a reader could see.
#[cfg(windows)]
fn report_path(path: &StdPath) -> String {
    path.to_string_lossy().replace('\\', "/")
}

/// The path as the report spells it. Nothing to rewrite here: `\` is a
/// legal character in a Unix filename, and replacing it would rename the
/// file in the report.
#[cfg(not(windows))]
fn report_path(path: &StdPath) -> String {
    path.to_string_lossy().into_owned()
}

/// The report for a path the walk itself could not open — a locked
/// directory, a loop, an entry the filesystem refused.
///
/// Carried rather than dropped, and a warning rather than a failure: one
/// unreadable directory must not end an audit of everything beside it,
/// and must not silently narrow it either. `--strict` is how a pipeline
/// asks for zero tolerance.
pub(crate) fn unreadable(path: &StdPath, reason: &str) -> FileReport {
    skipped(report_path(path), format_of(path), reason)
}

/// Every report a set of named paths produces, and the count of files
/// that were never text.
///
/// **Both surfaces come through here**, so neither can grow its own
/// idea of what a binary file is or what an unreadable directory costs.
/// A path the walk could not open becomes a report line rather than the
/// end of the run: one locked directory must not take the audit of
/// everything beside it with it, and must not vanish either.
pub(crate) fn tree(
    inputs: &[PathBuf],
    walk_options: &WalkOptions,
    options: &ScanOptions,
) -> Result<(Vec<FileReport>, usize), String> {
    let walked = walk::collect(inputs, walk_options)?;
    let scanned = walked
        .files
        .iter()
        .map(|target| scan_file(target, options))
        .collect();
    let (mut reports, binary) = partition(scanned);
    reports.extend(
        walked
            .unreadable
            .iter()
            .map(|(path, reason)| unreadable(path, reason)),
    );
    Ok((reports, binary))
}

pub(crate) fn scan_file(path: &PathBuf, options: &ScanOptions) -> Scanned {
    let file = report_path(path);
    let format = options.format.unwrap_or_else(|| format_of(path));

    match std::fs::read(path) {
        // Never a text candidate, so never a report. Counted, never
        // silent.
        Ok(bytes) if is_binary(&bytes) => Scanned::Binary,
        Ok(bytes) => Scanned::Read(Box::new(match String::from_utf8(bytes) {
            Ok(content) => scan_content(without_bom(&content), file, format, options),
            // Named rather than dropped. A file that looked like text
            // and was not is a file the reader would otherwise believe
            // was covered.
            Err(_) => skipped(file, format, "not UTF-8 text"),
        })),
        Err(error) => Scanned::Read(Box::new(skipped(file, format, &error.to_string()))),
    }
}

fn format_of(path: &StdPath) -> &'static str {
    resolve_format(None, path.file_name().and_then(|name| name.to_str()))
}

pub(crate) fn scan_content(
    content: &str,
    file: String,
    format: &str,
    options: &ScanOptions,
) -> FileReport {
    let addresses: Vec<Found> = extract::find(content, format)
        .into_iter()
        .filter(|found| found.survives(&options.kinds, &options.classes))
        .collect();

    let mut diagnostics = Vec::new();
    // A parse failure costs the key paths and nothing else — the byte
    // scan already ran. Said as a warning because the file was still
    // read: a broken config is the one most likely to hold the wrong
    // address, and failing the run on it would hide that.
    if let Some(message) = extract::parse_error(content, format) {
        diagnostics.push(Diagnostic {
            severity: "warning".to_string(),
            code: "unparsed".to_string(),
            message,
        });
    }

    let refused = addresses.iter().filter(|found| found.is_refusal()).count();
    FileReport {
        schema: SCHEMA,
        file,
        format: format.to_string(),
        summary: Summary {
            addresses: addresses.len() - refused,
            refused,
        },
        addresses,
        diagnostics,
    }
}

/// grep's convention: 0 found, 1 none found, 2 could not answer.
///
/// **A refusal does not move this.** It is a finding, not a failure —
/// the tool ran, read the text and declined to name it, which is a
/// result a caller can act on. `--strict` is for the pipeline that
/// wants an unresolved ambiguity to stop the build; without it, a
/// changelog full of version strings does not fail an audit.
pub(crate) fn exit_code(reports: &[FileReport], strict: bool) -> u8 {
    if strict
        && reports
            .iter()
            .any(|report| report.was_skipped() || report.summary.refused > 0)
    {
        return 2;
    }
    u8::from(!reports.iter().any(|report| report.summary.addresses > 0))
}

/// The human line: where it is, what it says, and what this tool made
/// of it.
pub(crate) fn describe(report: &FileReport, found: &Found) -> String {
    let verdict = match (&found.refused, &found.normalized, found.class) {
        (Some(refusal), _, _) => format!("refused {:?}", refusal.reason),
        (_, Some(normalized), Some(class)) => format!("{normalized}  {}", class.name()),
        _ => String::new(),
    };
    format!(
        "{}:{}:{}  {}  {verdict}",
        report.file, found.line, found.column, found.text
    )
}

/// The report for a file that was not read: named, warned about, and
/// not a failure by itself.
fn skipped(file: String, format: &'static str, reason: &str) -> FileReport {
    FileReport {
        schema: SCHEMA,
        file,
        format: format.to_string(),
        addresses: Vec::new(),
        diagnostics: vec![Diagnostic {
            severity: "warning".to_string(),
            code: "skipped".to_string(),
            message: reason.to_string(),
        }],
        summary: Summary {
            addresses: 0,
            refused: 0,
        },
    }
}

/// Drop a leading byte-order mark.
///
/// No editor shows it, and without this a log or a config written by
/// anything on Windows — Notepad, Excel, a PowerShell redirect — has
/// three invisible bytes shifting every column on its first line.
pub(crate) fn without_bom(content: &str) -> &str {
    content.strip_prefix('\u{feff}').unwrap_or(content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::TempTree;

    fn plain() -> ScanOptions {
        ScanOptions::default()
    }

    fn read(path: &PathBuf, options: &ScanOptions) -> FileReport {
        scan_file(path, options)
            .into_report()
            .expect("the file was a text candidate")
    }

    fn texts(report: &FileReport) -> Vec<&str> {
        report
            .addresses
            .iter()
            .map(|found| found.text.as_str())
            .collect()
    }

    #[test]
    fn a_document_with_addresses_exits_zero() {
        let report = scan_content(r#"{"bind":"10.0.0.5"}"#, "a.json".into(), "json", &plain());
        assert_eq!(texts(&report), ["10.0.0.5"]);
        assert_eq!(report.summary.addresses, 1);
        assert_eq!(exit_code(&[report], false), 0);
    }

    #[test]
    fn a_document_with_none_exits_one() {
        let report = scan_content(r#"{"a":"text"}"#, "a.json".into(), "json", &plain());
        assert_eq!(report.summary.addresses, 0);
        assert_eq!(exit_code(&[report], false), 1);
    }

    #[test]
    fn nothing_to_scan_exits_one() {
        assert_eq!(exit_code(&[], false), 1);
    }

    /// The exit-code rule the whole refusal design rests on: an
    /// ambiguity is a finding, not a failure, until a pipeline says
    /// otherwise.
    #[test]
    fn a_refusal_alone_is_not_a_finding_and_not_a_failure() {
        let report = scan_content("build 10.0.1 here", "a.txt".into(), "unknown", &plain());
        assert_eq!(report.summary.addresses, 0);
        assert_eq!(report.summary.refused, 1);
        assert_eq!(exit_code(std::slice::from_ref(&report), false), 1);
        assert_eq!(exit_code(&[report], true), 2, "--strict is opt-in");
    }

    /// A broken document loses its key paths and keeps its addresses.
    #[test]
    fn a_parse_failure_is_a_warning_and_the_scan_still_ran() {
        let report = scan_content("{not json 10.0.0.5", "a.json".into(), "json", &plain());
        assert_eq!(report.diagnostics.len(), 1);
        assert_eq!(report.diagnostics[0].severity, "warning");
        assert_eq!(texts(&report), ["10.0.0.5"]);
        assert!(!report.was_skipped());
        assert_eq!(exit_code(&[report], false), 0);
    }

    #[test]
    fn an_unreadable_file_is_reported_and_does_not_end_the_run() {
        let tree = TempTree::new("scan-unreadable");
        let report = read(&tree.path().join("gone.json"), &plain());
        assert!(report.was_skipped());
        assert_eq!(exit_code(std::slice::from_ref(&report), false), 1);
        assert_eq!(exit_code(&[report], true), 2);
    }

    #[test]
    fn a_binary_file_is_not_a_report() {
        let tree = TempTree::new("scan-binary");
        let file = tree.write_bytes("logo.png", &[0x89, 0x50, 0x4e, 0x47, 0x00, 0x1a]);
        assert_eq!(scan_file(&file, &plain()), Scanned::Binary);
        let binary_only = partition(vec![scan_file(&file, &plain())]).0;
        assert_eq!(
            exit_code(&binary_only, true),
            1,
            "a binary file never fails --strict"
        );
    }

    /// ripgrep's own test, and the reason it is that one: a NUL byte
    /// after the first 8 KiB belongs to a file this already read as
    /// text.
    #[test]
    fn binary_is_a_nul_byte_in_the_first_8_kib() {
        let tree = TempTree::new("scan-sniff");
        let mut late = vec![b'1'; BINARY_SNIFF_BYTES + 16];
        late[BINARY_SNIFF_BYTES + 8] = 0;
        let file = tree.write_bytes("late.txt", &late);
        assert_ne!(scan_file(&file, &plain()), Scanned::Binary);
    }

    #[test]
    fn the_format_comes_from_the_file_name() {
        let tree = TempTree::new("scan-format");
        let file = tree.write("access.log", "src=10.0.0.5 ok\n");
        let report = read(&file, &plain());
        assert_eq!(report.format, "log");
        assert_eq!(report.addresses[0].key.as_deref(), Some("src"));
    }

    /// A file with no reader still yields its addresses — the scan runs
    /// over bytes, and only the key path depends on the format.
    #[test]
    fn an_unknown_extension_still_yields_addresses() {
        let tree = TempTree::new("scan-unknown");
        let file = tree.write("main.tf", "cidr_block = \"10.0.0.0/16\"\n");
        let report = read(&file, &plain());
        assert_eq!(report.format, "unknown");
        assert_eq!(texts(&report), ["10.0.0.0/16"]);
        assert_eq!(report.addresses[0].key, None);
    }

    #[test]
    fn a_forced_format_overrides_the_file_name() {
        let tree = TempTree::new("scan-forced");
        let file = tree.write("data.json", "bind = \"10.0.0.5\"\n");
        let report = read(
            &file,
            &ScanOptions {
                format: Some("toml"),
                ..plain()
            },
        );
        assert_eq!(report.format, "toml");
        assert_eq!(report.addresses[0].key.as_deref(), Some("bind"));
    }

    #[test]
    fn a_kind_filter_keeps_only_that_kind() {
        let content = "a 10.0.0.1 b 2001:db8::1 c 10.0.0.0/8 d aa:bb:cc:dd:ee:ff";
        let report = scan_content(
            content,
            "a.txt".into(),
            "unknown",
            &ScanOptions {
                kinds: vec![Kind::Cidr],
                ..plain()
            },
        );
        assert_eq!(texts(&report), ["10.0.0.0/8"]);
    }

    #[test]
    fn a_class_filter_keeps_only_that_class() {
        let content = "a 10.0.0.1 b 8.8.8.8 c 127.0.0.1";
        let report = scan_content(
            content,
            "a.txt".into(),
            "unknown",
            &ScanOptions {
                classes: vec![Class::Global],
                ..plain()
            },
        );
        assert_eq!(texts(&report), ["8.8.8.8"]);
    }

    /// A filter narrows what this tool *claims*, never what it
    /// *declined to claim*. Dropping a refusal from `--class private`
    /// would hide the octal hazard from the person auditing an
    /// allow-list.
    #[test]
    fn a_filter_never_hides_a_refusal() {
        let content = "allow 010.1.1.1 and 8.8.8.8";
        let report = scan_content(
            content,
            "a.txt".into(),
            "unknown",
            &ScanOptions {
                classes: vec![Class::Private],
                ..plain()
            },
        );
        assert_eq!(texts(&report), ["010.1.1.1"]);
        assert_eq!(report.summary.refused, 1);
        assert_eq!(report.summary.addresses, 0);
    }

    #[test]
    fn the_human_line_carries_the_position_and_the_verdict() {
        let report = scan_content(r#"{"a":"10.0.0.5"}"#, "a.json".into(), "json", &plain());
        assert_eq!(
            describe(&report, &report.addresses[0]),
            "a.json:1:7  10.0.0.5  10.0.0.5  private"
        );
    }

    #[test]
    fn the_human_line_names_the_refusal() {
        let report = scan_content("010.1.1.1", "a.txt".into(), "unknown", &plain());
        assert!(
            describe(&report, &report.addresses[0]).contains("refused OctalHazard"),
            "{}",
            describe(&report, &report.addresses[0])
        );
    }
}

#[cfg(test)]
mod hazards {
    use super::*;

    /// Three invisible bytes that Notepad, Excel and a PowerShell
    /// redirect all add, and that would otherwise shift every column on
    /// the first line of a log.
    #[test]
    fn a_byte_order_mark_is_not_part_of_the_document() {
        assert_eq!(without_bom("\u{feff}abc"), "abc");
        assert_eq!(without_bom("abc"), "abc");
        // Only a leading one: elsewhere it is a zero-width no-break
        // space and belongs to the text.
        assert_eq!(without_bom("a\u{feff}b"), "a\u{feff}b");
    }
}
