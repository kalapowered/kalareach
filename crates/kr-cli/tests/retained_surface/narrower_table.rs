//! The entries of the narrower kind: the rules of a worker's input that refuse more than the
//! retained release's rule did.
//!
//! The table is empty while no such change has been made. An entry is made with the change that
//! needs it, and is held to this checkout by `the_entries_of_the_narrower_table_hold` and to every
//! release of its level by the check a landing runs.

use super::narrower::Narrower;

pub const NARROWER: &[Narrower] = &[];
