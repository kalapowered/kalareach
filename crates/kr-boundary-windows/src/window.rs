//! When the proof's search for a refusal is over.
//!
//! The search runs programs and queries of the log inside a window that ends before the proof's
//! deadline, so that the log's last words can still be read from the time kept after it. A run is
//! given its deadline less a short reserve for the end of its job and of its pipes, so a program or
//! a query that begins inside that last reserve of the window is cut at once and ends as timed out
//! without having failed at anything. That cut is the window's own end, and the search is over then;
//! it is not a failure of the proof, which would hide the log's last words. Every other failure of a
//! run is a failure of the proof at any time.

use std::time::{Duration, Instant};

/// Whether the search is over after a run inside it, at `now`.
///
/// After the window's end any result ends the search. Before it, only a run that was cut at its
/// deadline (`cut`) does, and only when the cut can have come from the window's end: when `now`
/// is within `reserve` of it.
#[must_use]
pub fn search_is_over(cut: bool, now: Instant, search_until: Instant, reserve: Duration) -> bool {
    now >= search_until || (cut && now + reserve >= search_until)
}
