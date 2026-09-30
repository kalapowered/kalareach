//! A physical terminal, measured against the canonical grid.
//!
//! The terminal engine keeps one grid and decides where the cursor is after any bytes. A physical
//! terminal decides the same thing for itself, and the two agree only as far as the terminal
//! implements the profile the engine follows. This crate finds out how far that is. It writes the
//! bytes of each step of a corpus to the terminal it runs in, asks where the cursor is with the
//! cursor position report, and compares the answer with the cursor of a canonical grid given the
//! same bytes.
//!
//! The comparison is a cursor position on purpose. It is the one thing every terminal can be asked
//! and answers in the same form, and it is what a wrong width, a different wrap rule or a
//! misplaced margin all end up moving.
//!
//! Every step starts from a full reset and a cleared screen, so a step's answer cannot depend on
//! the step before it, and every answer is read up to the reply to primary device attributes, which
//! every terminal gives and gives last, so a terminal that ignores a question does not stall the
//! run and one that answers late is not taken for the next step's.

pub mod corpus;
pub mod replies;
pub mod report;
pub mod run;

/// The reset every step starts from: full reset, out of the alternate screen, screen cleared, and
/// the cursor at the top left.
pub const RESET: &[u8] = b"\x1bc\x1b[?1049l\x1b[2J\x1b[H";

/// The question a step ends with: where is the cursor.
pub const CURSOR_POSITION: &[u8] = b"\x1b[6n";

/// The barrier: primary device attributes, which every terminal answers, and answers after every
/// question asked before it.
pub const BARRIER: &[u8] = b"\x1b[c";
