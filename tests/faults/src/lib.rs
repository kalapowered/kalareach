//! The fault harness: what a session's clients hold when their session is interrupted, restored
//! or raced, checked against what the session holds.
//!
//! Section 27 asks for fault tests and for snapshots restored in the middle of output and at
//! alternate-screen transitions, and section 29 for deterministic time, scripted peers and retained
//! traces. This crate is the harness those tests are written with. It links nothing into the
//! product: every seam it drives is one the product already offers its own tests.
//!
//! * [`corpus`]: an application's output, written the way the application wrote it, kept as a
//!   fixture a person can read.
//! * [`screen`]: a screen read by position, so two screens of the same content compare equal
//!   whatever row identifiers each was built with, and say where they differ when they do not.
//! * [`terminal`]: a model of a person's physical terminal, which reads the buffer switches as the
//!   xterm family does and says every side effect it performs.
//! * [`time`]: one simulated timeline, and every clock the product takes by injection read from
//!   it.
//! * [`restore`]: a worker's session fed a corpus through its own read-loop entry, and the two
//!   clients a person attaches with, attached at every point of it and checked against the
//!   session's own screen.

pub mod corpus;
pub mod restore;
pub mod screen;
pub mod terminal;
pub mod time;
