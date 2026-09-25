//! The application matrix, in a real session.
//!
//! Section 21's terminal-conformance row exercises the applications people run in a terminal and
//! checks alternate screens, paste, mouse, Unicode and query behaviour; section 27 adds CJK width,
//! combining marks, emoji sequences, bidirectional text, incomplete UTF-8, long control strings and
//! every advertised keyboard and mouse protocol. Each program here is a pinned release that
//! `scripts/run-conformance.sh` fetched once, started as the root of a real session under a worker
//! and driven through the session's own input path. Each case compares the worker's snapshot of
//! the canonical grid with the screen the program itself says it is showing, and shows that no
//! query the program asked reached the attached terminal.
//!
//! The cases are ignored in an ordinary test run, because the programs are fetched rather than
//! built by this workspace; the report's applications group runs them. Run without the fetched
//! programs, every case fails, saying how to fetch them.

// The session drives a Unix pseudo-terminal here; a console application on Windows is driven
// through the pseudo-console, which the Windows test machine qualifies.
#![cfg(unix)]

mod fzf;
mod harness;
mod htop;
mod lazygit;
mod neovim;
mod queries;
mod screen;
mod tmux;
