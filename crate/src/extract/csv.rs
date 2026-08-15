//! CSV, cell by cell.
//!
//! **Every row is data.** There is no header inference here, for the
//! same reason the sibling crates refuse it: a firewall export and a
//! netflow dump both have a header row and neither says so, and a tool
//! that guessed would silently drop the first row's addresses from the
//! report — or worse, name every column after a cell that happened to
//! be a hostname.
//!
//! So a key is a coordinate: `[2][3]` is the fourth cell of the third
//! row, both counted from zero. That is a locator a reader can act on
//! with no interpretation attached to it.

use super::{KeySpan, lines};

/// The byte between cells. Tab-separated files are the same grammar
/// with a different one, and reading a tab row on commas made the whole
/// row one cell — so every address in it claimed column `[row][0]`, a
/// coordinate that is a locator a reader acts on.
pub(crate) const COMMA: char = ',';
pub(crate) const TAB: char = '\t';

pub(crate) fn keys(text: &str, delimiter: char) -> Vec<KeySpan> {
    let mut spans = Vec::new();
    for (row, (offset, line)) in lines(text).enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        for (column, cell) in cells(line, delimiter).into_iter().enumerate() {
            spans.push(KeySpan {
                start: offset + cell.start,
                end: offset + cell.end,
                path: format!("[{row}][{column}]"),
            });
        }
    }
    spans
}

struct Cell {
    start: usize,
    end: usize,
}

/// Split a line on commas outside quotes.
///
/// A quoted cell may hold a comma, which is the entire reason quoting
/// exists in these files — and an address list in one cell
/// (`"10.0.0.1,10.0.0.2"`) is a shape that actually occurs.
fn cells(line: &str, delimiter: char) -> Vec<Cell> {
    let mut start = 0;
    let mut quoted = false;
    let mut boundaries = Vec::new();
    for (index, character) in line.char_indices() {
        if character == '"' {
            quoted = !quoted;
            continue;
        }
        if character == delimiter && !quoted {
            boundaries.push(Cell { start, end: index });
            start = index + 1;
        }
    }
    boundaries.push(Cell {
        start,
        end: line.len(),
    });
    boundaries
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str, needle: &str) -> Option<String> {
        let at = text.find(needle).expect("the needle is in the text");
        keys(text, COMMA)
            .into_iter()
            .find(|span| span.start <= at && at < span.end)
            .map(|span| span.path)
    }

    #[test]
    fn a_cell_is_named_by_its_coordinate() {
        let text = "host,ip\nweb,10.0.0.5\n";
        assert_eq!(at(text, "10.0.0.5").as_deref(), Some("[1][1]"));
    }

    /// No header inference, so the first row is data like any other and
    /// its addresses are reported.
    #[test]
    fn the_first_row_is_data_like_any_other() {
        assert_eq!(at("10.0.0.1,x\n", "10.0.0.1").as_deref(), Some("[0][0]"));
    }

    #[test]
    fn a_quoted_cell_may_hold_a_comma() {
        let text = "a,\"10.0.0.1,10.0.0.2\",b\n";
        assert_eq!(at(text, "10.0.0.1").as_deref(), Some("[0][1]"));
        assert_eq!(at(text, "10.0.0.2").as_deref(), Some("[0][1]"));
    }

    #[test]
    fn a_ragged_row_is_not_a_failure() {
        let text = "a,b,c\n10.0.0.1\n";
        assert_eq!(at(text, "10.0.0.1").as_deref(), Some("[1][0]"));
    }

    /// The delimiter is the whole fix. Read on commas, a tab row is one
    /// cell, so every address in it claimed `[row][0]` — three different
    /// addresses on one line, all reporting the same coordinate.
    #[test]
    fn a_tab_row_is_cells_under_tab_and_one_cell_under_comma() {
        let text = "host\tmgmt\tgw\nweb01\t10.0.0.1\t10.0.0.254\n";
        let tabbed: Vec<String> = keys(text, TAB).iter().map(|s| s.path.clone()).collect();
        assert_eq!(
            tabbed,
            ["[0][0]", "[0][1]", "[0][2]", "[1][0]", "[1][1]", "[1][2]"]
        );
        let comma: Vec<String> = keys(text, COMMA).iter().map(|s| s.path.clone()).collect();
        assert_eq!(comma, ["[0][0]", "[1][0]"]);
    }

    #[test]
    fn a_blank_line_has_no_cells() {
        assert!(keys("\n   \n", COMMA).is_empty());
    }
}
