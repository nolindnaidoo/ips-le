//! A wall-clock ceiling on a seeded corpus, and three shape checks on
//! how the clock moves.
//!
//! A sibling in this family was fifty times slower than the rest for a
//! whole release and nothing noticed, because nothing measured it. The
//! ceilings here are deliberately loose — a shared runner is not a
//! benchmark rig — and exist to catch an order of magnitude, not a
//! percent.
//!
//! **The corpus is generated from a fixed seed**, not checked in: five
//! hundred near-identical config files in git would be five hundred a
//! reviewer has to ignore, and the generator is twenty lines. The seed
//! is constant, so two runs measure the same corpus.
//!
//! Gated behind `IPS_LE_BUDGET` and run by CI on one platform with
//! `--test-threads=1`; a timing assertion measured against five other
//! tests on the same cores is noise. **A skipped run says so by name.**
//!
//! ## The quadratic this pins
//!
//! `PositionIndex` reports a column in UTF-16 code units, and it used to
//! count them from the start of the line on **every** lookup. On an
//! ASCII document that never showed: a byte offset *is* a UTF-16 offset,
//! so the column was arithmetic. On a document with one `café` in it the
//! fast path was gone and every address on a long line re-counted the
//! whole prefix — quadratic in the addresses per line, and invisible to
//! any suite whose long-line case was ASCII.
//!
//! Measured here, debug build, Apple M-series laptop, macOS 15, 2026-08:
//!
//! | case | before checkpoints | after |
//! |---|---|---|
//! | 5,000 addresses on one non-ASCII line | 3.74 s | 0.077 s |
//! | 20,000 addresses on one non-ASCII line | 62.2 s | 0.302 s |
//!
//! Both assertions below catch it, and that is on purpose: 62 s is far
//! past the absolute ceiling, and 16.6× for four times the work is far
//! past the linearity bound. A ceiling alone can be met by something
//! quadratic and small; a ratio alone can be met by something linear and
//! uniformly slow.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

const BINARY: &str = env!("CARGO_BIN_EXE_ips-le");

const SEED: u64 = 0x1b5e_0b1d_2026_0812;
const FILES: usize = 500;

/// **10× the local measurement**, recorded with the machine it came
/// from: 0.172 s for the 500-file corpus below, debug build, Apple
/// M-series laptop, macOS 15, 2026-08. Ten times that leaves a shared
/// runner room to be several times slower and still be right; it does
/// not leave room for an order of magnitude.
const TREE_CEILING: Duration = Duration::from_millis(1_800);

/// 10× the local measurement for 20,000 addresses on one non-ASCII line:
/// 0.302 s. The same document cost 62.2 s before the position index kept
/// checkpoints.
const LONG_LINE_CEILING: Duration = Duration::from_secs(3);

/// Four times the work, at most six times the clock.
const LINEARITY: f64 = 6.0;

/// Addresses on the pinned long line. Four times the smaller run, so the
/// two together are the linearity check as well as the ceiling.
const LONG_LINE_ADDRESSES: usize = 20_000;
const SHORT_LINE_ADDRESSES: usize = 5_000;

fn enabled(name: &str) -> bool {
    if std::env::var_os("IPS_LE_BUDGET").is_some() {
        return true;
    }
    eprintln!("SKIPPED {name}: set IPS_LE_BUDGET to run it");
    false
}

/// xorshift64*, four lines and identical on every platform.
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
}

struct Tree {
    root: PathBuf,
}

impl Tree {
    fn new(name: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("ips-le-budget-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("a temporary directory");
        Self { root }
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

/// The extensions an infrastructure directory actually holds, so the
/// corpus exercises every key reader and the fallback rather than one.
const EXTENSIONS: [&str; 10] = [
    "json", "yaml", "toml", "ini", "env", "csv", "log", "tf", "conf", "txt",
];

/// A tree of config- and log-shaped text: mostly ordinary lines, some
/// addresses, and a steady supply of the timestamps and durations the
/// scanner has to keep declining.
fn populate(root: &Path, prefix: &str) {
    let mut seeded = Seeded(SEED);
    for index in 0..FILES {
        let extension = EXTENSIONS[index % EXTENSIONS.len()];
        let mut content = String::with_capacity(4_000);
        for line in 0..80 {
            let _ = match seeded.below(5) {
                0 => writeln!(
                    content,
                    "  peer_ip = \"10.{}.{}.{}\"",
                    seeded.below(256),
                    seeded.below(256),
                    line % 256
                ),
                1 => writeln!(
                    content,
                    "  ts=2026-08-12T10:{:02}:{:02}Z took={line}.25ms status=200",
                    line % 60,
                    (line * 7) % 60
                ),
                2 => writeln!(content, "  # a comment with no address in it at all"),
                _ => writeln!(
                    content,
                    "  value_{line} = \"a plain line of configuration text number {line}\""
                ),
            };
        }
        let target = format!("{prefix}pkg{:02}/file{index:03}.{extension}", index % 25);
        write_at(root, &target, &content);
    }
}

fn write_at(root: &Path, relative: &str, contents: &str) {
    let target = root.join(relative);
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent).expect("a parent directory");
    }
    std::fs::write(&target, contents).expect("a file");
}

/// One timed run, with the report thrown away — writing megabytes of
/// JSON to a pipe nobody reads would be timing the pipe.
fn measure(target: &Path) -> Duration {
    let started = Instant::now();
    let output = Command::new(BINARY)
        .arg(target)
        .output()
        .expect("the binary runs");
    let elapsed = started.elapsed();
    assert_eq!(
        output.status.code(),
        Some(0),
        "the scan did not succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    elapsed
}

/// The fastest of three. A shared runner's slowest run measures the
/// runner; its fastest measures the code, which is what a ceiling is
/// about.
fn best_of_three(target: &Path) -> Duration {
    (0..3)
        .map(|_| measure(target))
        .min()
        .expect("three measurements")
}

/// One line, `count` addresses, and — when `non_ascii` — a two-byte
/// character before every one of them.
///
/// The `café` is the whole point of the case: it is what removes the
/// ASCII fast path from the position index, which is where the quadratic
/// lived and where no ASCII long-line case could ever have found it.
fn one_long_line(count: usize, non_ascii: bool) -> String {
    let mut content = String::with_capacity(count * 24);
    for index in 0..count {
        let _ = if non_ascii {
            write!(content, "caf\u{e9} {index} 10.0.0.{} ", index % 256)
        } else {
            write!(
                content,
                "peer{index}_ip=10.{}.{}.{} ",
                index / 65_536,
                (index / 256) % 256,
                index % 256
            )
        };
    }
    content
}

fn ratio(one: Duration, four: Duration) -> f64 {
    four.as_secs_f64() / one.as_secs_f64().max(f64::EPSILON)
}

#[test]
fn a_five_hundred_file_tree_scans_inside_its_budget() {
    if !enabled("a_five_hundred_file_tree_scans_inside_its_budget") {
        return;
    }
    let tree = Tree::new("single");
    populate(tree.path(), "");

    let elapsed = best_of_three(tree.path());
    eprintln!("budget: {FILES} files in {elapsed:?} (ceiling {TREE_CEILING:?}, seed {SEED:#x})");
    assert!(
        elapsed <= TREE_CEILING,
        "scanning {FILES} files took {elapsed:?}, over the {TREE_CEILING:?} ceiling — that is \
         ten times the recorded local measurement, so this is an order of magnitude and not a \
         slow runner"
    );
}

#[test]
fn four_times_the_tree_is_not_six_times_the_clock() {
    if !enabled("four_times_the_tree_is_not_six_times_the_clock") {
        return;
    }
    let one = Tree::new("linear-one");
    populate(one.path(), "");
    let four = Tree::new("linear-four");
    for copy in 0..4 {
        populate(four.path(), &format!("copy{copy}-"));
    }

    let single = best_of_three(one.path());
    let quadrupled = best_of_three(four.path());
    let ratio = ratio(single, quadrupled);
    eprintln!(
        "budget: {single:?} for {FILES} files, {quadrupled:?} for {}, ratio {ratio:.2}",
        FILES * 4
    );
    assert!(
        ratio <= LINEARITY,
        "four times the tree cost {ratio:.2}× the time (limit {LINEARITY}×) — the walk is not \
         linear in the number of files"
    );
}

/// The other direction a document grows. Key lookup is a binary search
/// over the format reader's spans and the position lookup is a binary
/// search over the line starts; anything that walks either list per
/// address shows up here and nowhere else.
#[test]
fn four_times_the_addresses_in_one_file_is_not_six_times_the_clock() {
    if !enabled("four_times_the_addresses_in_one_file_is_not_six_times_the_clock") {
        return;
    }
    let tree = Tree::new("dense");
    let one = tree.write("one.log", &one_long_line(SHORT_LINE_ADDRESSES, false));
    let four = tree.write("four.log", &one_long_line(LONG_LINE_ADDRESSES, false));

    let single = best_of_three(&one);
    let quadrupled = best_of_three(&four);
    let ratio = ratio(single, quadrupled);
    eprintln!(
        "budget: {single:?} for {SHORT_LINE_ADDRESSES} addresses on one line, \
         {quadrupled:?} for {LONG_LINE_ADDRESSES}, ratio {ratio:.2}"
    );
    assert!(
        ratio <= LINEARITY,
        "four times the addresses in one document cost {ratio:.2}× the time (limit {LINEARITY}×)"
    );
}

/// **The regression this file exists to pin.** One line, no ASCII fast
/// path, and every address on it asking for a column.
///
/// Before `PositionIndex` kept checkpoints, this document cost 62.2 s
/// where its quarter-size twin cost 3.74 s — a ratio of 16.6, and an
/// absolute time twenty times the ceiling below. Both assertions fail on
/// that, and neither can be satisfied by making the tool uniformly
/// slower or uniformly smaller.
#[test]
fn a_long_non_ascii_line_stays_inside_its_budget_and_scales_linearly() {
    if !enabled("a_long_non_ascii_line_stays_inside_its_budget_and_scales_linearly") {
        return;
    }
    let tree = Tree::new("non-ascii");
    let short = tree.write("short.txt", &one_long_line(SHORT_LINE_ADDRESSES, true));
    let long = tree.write("long.txt", &one_long_line(LONG_LINE_ADDRESSES, true));

    let quick = best_of_three(&short);
    let elapsed = best_of_three(&long);
    let ratio = ratio(quick, elapsed);
    eprintln!(
        "budget: {quick:?} for {SHORT_LINE_ADDRESSES} non-ASCII addresses on one line, \
         {elapsed:?} for {LONG_LINE_ADDRESSES}, ratio {ratio:.2} \
         (ceiling {LONG_LINE_CEILING:?})"
    );

    assert!(
        elapsed <= LONG_LINE_CEILING,
        "{LONG_LINE_ADDRESSES} addresses on one non-ASCII line took {elapsed:?}, over the \
         {LONG_LINE_CEILING:?} ceiling — the position index is counting UTF-16 units from the \
         line start again"
    );
    assert!(
        ratio <= LINEARITY,
        "four times the addresses on one non-ASCII line cost {ratio:.2}× the time (limit \
         {LINEARITY}×) — that is the shape of a square, and it is the exact bug the position \
         index's checkpoints removed"
    );
}
