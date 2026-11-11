//! When the proof's search for a refusal is over.
//!
//! The search runs programs and queries of the log inside a window that ends before the proof's
//! deadline, so that the log's last words can still be read from the time kept after it. A run is
//! given the earlier of the window's end and a bound of its own, and it is cut at that deadline. A
//! run that the window's end cut ends as timed out without having failed at anything: the search is
//! over then, and it is not a failure of the proof, which would hide the log's last words. What cut
//! a run is known from the deadline that it was given, never from the clock at the time it returned:
//! a run that ended at its own bound, and every failure of a run (it could not start, a pipe failed,
//! it ended badly), is a failure of the proof at any time, also after the window's end.

use std::time::Instant;

/// A run's deadline inside the window, and whether the window's end set it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bound {
    /// The deadline the run is given.
    pub by: Instant,
    /// Whether that deadline is the window's end and not the run's own bound.
    pub by_the_window: bool,
}

/// The deadline of a run that may take until `own` and must end by `window_end`.
#[must_use]
pub fn bound(window_end: Instant, own: Instant) -> Bound {
    Bound {
        by: window_end.min(own),
        by_the_window: window_end <= own,
    }
}

/// Whether the application-control log may be asked after a launch was refused: only while the
/// search's own end has not passed. A refusal that comes back after that end is the end of the
/// search; asking the log then would fail on the end itself, and the proof would fail with that
/// error and not with the search's own account of its launches and the log's last words.
#[must_use]
pub fn may_ask_the_log(now: Instant, search_until: Instant) -> bool {
    now < search_until
}

/// Whether the search is over after a run that was given `bound`: only a run that was cut at its
/// deadline (`cut`), when that deadline was the window's end.
#[must_use]
pub fn search_is_over(cut: bool, bound: Bound) -> bool {
    cut && bound.by_the_window
}
