//! Turning what the caller named into the list of files to read.
//!
//! Directories are walked with ripgrep's `ignore`, so "what this tool
//! reads" and "what ripgrep reads" are the same answer — which is the
//! answer a person auditing a repository already has in their head. A
//! file named explicitly is always read, ignore rules included: you
//! asked for it.
//!
//! There is no format filter, and here that is the point rather than a
//! precaution. An address is as likely to sit in a `.tf`, a `.rules`, a
//! `.sql` or a rotated log as in a config this crate has a reader for,
//! and every one of those still gets the full byte scan.
//!
//! Each crate in this family stands on its own: no shared crate, no
//! published core, and nothing holding this file equal to the similar
//! ones in the sibling repos.

use std::path::{Path as StdPath, PathBuf};

#[derive(Debug, Clone)]
pub(crate) struct WalkOptions {
    pub(crate) hidden: bool,
    pub(crate) respect_ignore: bool,
}

impl Default for WalkOptions {
    fn default() -> Self {
        Self {
            hidden: false,
            respect_ignore: true,
        }
    }
}

/// What a walk reached, and what it could not.
///
/// **An entry the walk cannot read is carried, not fatal.** Aborting on
/// one made a single locked directory hide the whole tree: the run
/// exited 2 and wrote no reports at all, so an audit of a repository
/// answered nothing because one directory in it was unreadable. Exit 2
/// means the *question* was malformed — a path that is not there, an
/// unknown flag — never a directory the filesystem refused.
#[derive(Debug, Default)]
pub(crate) struct Walked {
    pub(crate) files: Vec<PathBuf>,
    /// Each path the walk could not read, with the reason, in path
    /// order. Both surfaces turn these into `skipped` reports: named on
    /// stderr, carried in the JSON, failing `--strict`, never silent.
    pub(crate) unreadable: Vec<(PathBuf, String)>,
}

/// Collect every file to read, in a stable order.
///
/// The sort is not cosmetic: `ignore` makes no ordering guarantee, and
/// a report whose lines move between two runs over an unchanged tree
/// cannot be diffed — which is most of what a report in CI is for.
pub(crate) fn collect(inputs: &[PathBuf], options: &WalkOptions) -> Result<Walked, String> {
    let mut walked = Walked::default();

    for input in inputs {
        // A path the caller *named* and that is not there is a malformed
        // question, and stays a refusal. What the walk finds underneath
        // one is a fact about the tree.
        let metadata =
            std::fs::metadata(input).map_err(|error| format!("{}: {error}", input.display()))?;

        if metadata.is_file() {
            walked.files.push(input.clone());
            continue;
        }

        let found = walk_directory(input, options);
        walked.files.extend(found.files);
        walked.unreadable.extend(found.unreadable);
    }

    walked.files.sort();
    walked.files.dedup();
    walked.unreadable.sort();
    walked.unreadable.dedup();
    Ok(walked)
}

fn walk_directory(root: &StdPath, options: &WalkOptions) -> Walked {
    let mut builder = ignore::WalkBuilder::new(root);
    builder
        .hidden(!options.hidden)
        .git_ignore(options.respect_ignore)
        .git_global(options.respect_ignore)
        .git_exclude(options.respect_ignore)
        .ignore(options.respect_ignore)
        .parents(options.respect_ignore)
        // Never followed. A link out of the tree would have this
        // reading files the caller did not point it at, and reporting
        // their paths as though they were part of the audit.
        .follow_links(false);

    let mut walked = Walked::default();
    for entry in builder.build() {
        match entry {
            Ok(entry) if entry.file_type().is_some_and(|kind| kind.is_file()) => {
                walked.files.push(entry.into_path());
            }
            // A directory, a FIFO, a socket: reached, and never a text
            // candidate. Reading a named pipe would block forever.
            Ok(_) => {}
            Err(error) => walked.unreadable.push(refusal(&error, root)),
        }
    }
    walked
}

/// The path the walk could not read, and why, in the reader's terms.
///
/// `ignore`'s own message repeats the path inside the reason; the io
/// error alone is what a report line wants beside the name it already
/// carries.
fn refusal(error: &ignore::Error, root: &StdPath) -> (PathBuf, String) {
    let path = match error {
        ignore::Error::WithPath { path, .. } => path.clone(),
        ignore::Error::Loop { child, .. } => child.clone(),
        // Nothing else the walker produces names a path; the root is
        // then the most specific thing that can honestly be reported.
        _ => root.to_path_buf(),
    };
    let reason = error
        .io_error()
        .map_or_else(|| error.to_string(), std::string::ToString::to_string);
    (path, reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::TempTree;

    fn names(files: &[PathBuf]) -> Vec<String> {
        files
            .iter()
            .map(|path| {
                path.file_name()
                    .expect("a file name")
                    .to_string_lossy()
                    .into_owned()
            })
            .collect()
    }

    fn files(inputs: &[PathBuf], options: &WalkOptions) -> Vec<PathBuf> {
        collect(inputs, options).expect("walks").files
    }

    #[test]
    fn a_named_file_is_the_whole_walk() {
        let tree = TempTree::new("walk-one");
        let file = tree.write("a.json", "{}");
        assert_eq!(names(&files(&[file], &WalkOptions::default())), ["a.json"]);
    }

    #[test]
    fn a_directory_is_walked_in_a_stable_order() {
        let tree = TempTree::new("walk-order");
        for name in ["z.json", "a.json", "m.json"] {
            tree.write(name, "{}");
        }
        let first = files(&[tree.path().to_path_buf()], &WalkOptions::default());
        let again = files(&[tree.path().to_path_buf()], &WalkOptions::default());
        assert_eq!(names(&first), ["a.json", "m.json", "z.json"]);
        assert_eq!(first, again);
    }

    /// Every text file, whatever its extension. An address is as likely
    /// to sit in a Terraform file or a rotated log as in a config.
    #[test]
    fn files_of_every_extension_are_walked() {
        let tree = TempTree::new("walk-any");
        for name in ["a.json", "main.tf", "access.log.1", "Makefile"] {
            tree.write(name, "x");
        }
        let walked = files(&[tree.path().to_path_buf()], &WalkOptions::default());
        assert_eq!(walked.len(), 4);
    }

    #[test]
    fn ignored_files_are_skipped_and_read_on_request() {
        let tree = TempTree::new("walk-ignore");
        tree.mkdir(".git");
        tree.write(".gitignore", "ignored.log\n");
        tree.write("ignored.log", "10.0.0.1\n");
        tree.write("kept.log", "10.0.0.2\n");

        let walked = files(&[tree.path().to_path_buf()], &WalkOptions::default());
        assert!(names(&walked).contains(&"kept.log".to_string()));
        assert!(!names(&walked).contains(&"ignored.log".to_string()));

        let all = files(
            &[tree.path().to_path_buf()],
            &WalkOptions {
                respect_ignore: false,
                ..WalkOptions::default()
            },
        );
        assert!(names(&all).contains(&"ignored.log".to_string()));
    }

    #[test]
    fn hidden_files_are_read_on_request() {
        let tree = TempTree::new("walk-hidden");
        tree.write(".hidden.json", "{}");
        let default = files(&[tree.path().to_path_buf()], &WalkOptions::default());
        assert!(default.is_empty());

        let all = files(
            &[tree.path().to_path_buf()],
            &WalkOptions {
                hidden: true,
                ..WalkOptions::default()
            },
        );
        assert_eq!(names(&all), [".hidden.json"]);
    }

    /// Intent beats configuration: naming a file is asking for it.
    #[test]
    fn an_explicitly_named_file_beats_the_ignore_rules() {
        let tree = TempTree::new("walk-explicit");
        tree.mkdir(".git");
        tree.write(".gitignore", ".hidden.json\n");
        let file = tree.write(".hidden.json", "{}");
        let walked = files(&[file], &WalkOptions::default());
        assert_eq!(names(&walked), [".hidden.json"]);
    }

    #[test]
    fn a_missing_input_is_refused_by_name() {
        let tree = TempTree::new("walk-missing");
        let error =
            collect(&[tree.path().join("nope")], &WalkOptions::default()).expect_err("a refusal");
        assert!(error.contains("nope"), "{error}");
    }

    #[test]
    fn the_same_file_named_twice_is_read_once() {
        let tree = TempTree::new("walk-dedupe");
        let file = tree.write("a.json", "{}");
        let walked = files(&[file.clone(), file], &WalkOptions::default());
        assert_eq!(walked.len(), 1);
    }

    /// One locked directory used to end the whole run: `collect` turned
    /// the walker's error into a refusal, so a tree of ten thousand
    /// readable files answered nothing. It is carried now, and the files
    /// beside it are still walked.
    #[cfg(unix)]
    #[test]
    fn a_directory_the_walk_cannot_read_is_carried_and_never_fatal() {
        use std::os::unix::fs::PermissionsExt as _;

        let tree = TempTree::new("walk-locked");
        tree.write("kept.log", "10.0.0.1\n");
        let locked = tree.mkdir("locked");
        tree.write("locked/hidden.log", "10.0.0.2\n");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000))
            .expect("permissions");

        let walked = collect(&[tree.path().to_path_buf()], &WalkOptions::default());
        // Restored before asserting, or a failure leaves a directory the
        // cleanup cannot remove.
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755))
            .expect("permissions");

        let walked = walked.expect("an unreadable directory is not a malformed question");
        assert!(names(&walked.files).contains(&"kept.log".to_string()));
        // A runner that reads a 0o000 directory anyway (root) walks into
        // it instead, which is the filesystem answering rather than this
        // code — either way the readable half survives.
        assert!(
            walked.unreadable.len() == 1
                || names(&walked.files).contains(&"hidden.log".to_string()),
            "{walked:?}"
        );
    }
}
