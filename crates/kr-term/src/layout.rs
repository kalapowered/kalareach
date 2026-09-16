//! The canonical data layout the resident budgets are defined against.
//!
//! Section 8 gives a session a 64 MiB budget for its canonical screens, and a geometry is admitted
//! or refused by what it would reserve inside that budget. So the footprint is a promise about the
//! product: this geometry fits and that one does not. A promise cannot be read out of
//! `size_of`. The same records are not the same size on every host: a row record of the pinned
//! grid library is 144 bytes on macOS and 136 bytes on Linux and Windows, because every row
//! carries a lock for the application data a front end may attach to it, and what a
//! `std::sync::Mutex` costs is each platform's own business. A model built on `size_of` would
//! admit a geometry on one supported host and refuse it on another, and the fixtures that record
//! the boundary would only be true of the machine that generated them.
//!
//! Every figure here is therefore fixed, and every figure is the largest that record is on any
//! host KalaReach supports. Two things follow. The same geometry reserves the same bytes and is
//! admitted or refused the same way everywhere. And the reservation still bounds what the host
//! actually allocates, which is the whole point of admitting against a budget: each figure is
//! asserted below against the type the pinned library really uses, so a host, a toolchain or a
//! library revision whose record grew past the figure fails to build here rather than quietly
//! reserving less than it allocates.
//!
//! A host whose records are smaller reserves the figure anyway. That direction is safe, because
//! the session then holds room it never needs, and it is what keeps the budget one number.

use wezterm_term::color::ColorAttribute;
use wezterm_term::{Cell, CellAttributes, Line};

use crate::grid::GridAlert;
use crate::title::SavedTitle;

/// What a `String` or a `Vec` costs beyond the bytes it holds: the pointer, the length and the
/// capacity.
pub(crate) const HANDLE_BYTES: u64 = 24;

/// What one pointer-sized integer costs.
pub(crate) const WORD_BYTES: u64 = 8;

/// What one row record costs in the array its screen keeps it in.
///
/// The largest of the supported hosts: 144 bytes, which is what a row is on macOS. The cell
/// storage, the semantic zones, the sequence number, the line bits and the lock for the
/// application data a front end may attach.
pub(crate) const ROW_RECORD_BYTES: u64 = 144;

/// What one cell costs in the vector form of a row.
pub(crate) const CELL_BYTES: u64 = 24;

/// What the packed attributes beside a cell cost, before the allocation a cell keeps for the
/// attributes the packed form cannot hold.
pub(crate) const CELL_ATTRIBUTES_BYTES: u64 = 16;

/// What one colour attribute costs.
pub(crate) const COLOR_ATTRIBUTE_BYTES: u64 = 20;

/// What one hyperlink object's own fields cost, before the bytes its strings hold.
pub(crate) const HYPERLINK_BYTES: u64 = 80;

/// What one key and value pair costs in a hyperlink's parameter table.
pub(crate) const TABLE_PAIR_BYTES: u64 = 48;

/// What one alert record costs in the alert list, before the text it carries.
pub(crate) const ALERT_RECORD_BYTES: u64 = 48;

/// What one entry of the virtual title stack costs, before the titles it holds.
pub(crate) const SAVED_TITLE_BYTES: u64 = 48;

// Each figure above against the type it stands for, on the host this build is for. A record that
// grew past its figure stops the build: the alternative is a session that reserves less than it
// allocates, which is the one thing the budget exists to prevent.
const _: () = assert!(HANDLE_BYTES >= size_of::<String>() as u64);
const _: () = assert!(HANDLE_BYTES >= size_of::<Vec<u8>>() as u64);
const _: () = assert!(HANDLE_BYTES >= size_of::<Vec<u32>>() as u64);
const _: () = assert!(HANDLE_BYTES >= size_of::<Vec<usize>>() as u64);
const _: () = assert!(WORD_BYTES >= size_of::<usize>() as u64);
const _: () = assert!(ROW_RECORD_BYTES >= size_of::<Line>() as u64);
const _: () = assert!(CELL_BYTES >= size_of::<Cell>() as u64);
const _: () = assert!(CELL_ATTRIBUTES_BYTES >= size_of::<CellAttributes>() as u64);
const _: () = assert!(COLOR_ATTRIBUTE_BYTES >= size_of::<ColorAttribute>() as u64);
const _: () =
    assert!(HYPERLINK_BYTES >= size_of::<wezterm_escape_parser::hyperlink::Hyperlink>() as u64);
const _: () = assert!(TABLE_PAIR_BYTES >= size_of::<(String, String)>() as u64);
const _: () = assert!(ALERT_RECORD_BYTES >= size_of::<GridAlert>() as u64);
const _: () = assert!(SAVED_TITLE_BYTES >= size_of::<SavedTitle>() as u64);
