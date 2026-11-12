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

/// How a query of the log came to an end, as far as the search's end is concerned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryEnd {
    /// The query could not be made or did not answer for a reason of its own (it could not start, a
    /// pipe failed, it ended badly, its answer could not be read): a failure of the proof at any
    /// time.
    Failed,
    /// The deadline the query was given had passed before it started, whether between the test that
    /// allowed it and the query itself or before its program could be started.
    DeadlinePassed,
    /// The query was cut at its deadline. `by_the_deadline` says whether the deadline it was given
    /// set that end, and not a bound of its own.
    Cut {
        /// Whether the window's end set the deadline.
        by_the_deadline: bool,
    },
}

/// How a query whose program could not start because its deadline had passed came to an end. When
/// the search's own end set that deadline, it is the search's end; when the query's own bound did
/// (the earlier of the two), the search's deadline has not passed, and the query has failed.
#[must_use]
pub fn launch_deadline_end(by_the_deadline: bool) -> QueryEnd {
    if by_the_deadline {
        QueryEnd::DeadlinePassed
    } else {
        QueryEnd::Failed
    }
}

/// Whether a query that came to this end is the end of the search: the search's own end caused it,
/// whether the query was cut at it or never started because it had passed. Any other end is a
/// failure of the proof, which would hide the log's last words if it were taken for the search's end.
#[must_use]
pub fn query_ends_the_search(end: QueryEnd) -> bool {
    matches!(
        end,
        QueryEnd::DeadlinePassed
            | QueryEnd::Cut {
                by_the_deadline: true
            }
    )
}
