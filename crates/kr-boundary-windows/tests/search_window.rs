//! When the proof's search for a refusal is over: only a run that was cut at a deadline that the
//! window's own end set ends the search. A run's own bound, and every failure of a run (it could
//! not start, a pipe failed, it ended badly), is the proof's failure at any time, near the window's
//! end or after it.

use std::time::{Duration, Instant};

use kr_boundary_windows::window::{
    Next, QueryEnd, QueryResult, bound, launch_deadline_end, may_ask_the_log, next_after_a_query,
    query_ends_the_search, search_is_over,
};

#[test]
fn a_run_given_the_windows_end_has_it_as_its_deadline_and_says_so() {
    let end = Instant::now() + Duration::from_secs(60);
    let own = end + Duration::from_secs(30);
    let given = bound(end, own);
    assert_eq!(given.by, end);
    assert!(given.by_the_window);
}

#[test]
fn a_run_given_its_own_bound_has_it_as_its_deadline_and_does_not_say_so() {
    let end = Instant::now() + Duration::from_secs(60);
    let own = end - Duration::from_millis(1);
    let given = bound(end, own);
    assert_eq!(given.by, own);
    assert!(
        !given.by_the_window,
        "a bound 1 ms inside the window is the run's own"
    );
}

#[test]
fn a_bound_that_is_the_windows_end_to_the_instant_is_the_windows() {
    let end = Instant::now() + Duration::from_secs(60);
    assert!(bound(end, end).by_the_window);
}

#[test]
fn a_run_cut_at_the_windows_end_ends_the_search() {
    let end = Instant::now() + Duration::from_secs(60);
    assert!(search_is_over(
        true,
        bound(end, end + Duration::from_secs(30))
    ));
}

#[test]
fn a_run_cut_at_its_own_bound_does_not_end_the_search_however_near_the_end_it_was() {
    let end = Instant::now() + Duration::from_secs(60);
    for before in [
        Duration::from_millis(1),
        Duration::from_millis(1_500),
        Duration::from_secs(3),
    ] {
        assert!(
            !search_is_over(true, bound(end, end - before)),
            "a run cut {before:?} before the window's end by its own bound"
        );
    }
}

#[test]
fn a_run_that_failed_otherwise_never_ends_the_search_whatever_bound_it_had() {
    let end = Instant::now() + Duration::from_secs(60);
    for own in [
        end - Duration::from_secs(3),
        end - Duration::from_millis(1_500),
        end,
        end + Duration::from_secs(30),
    ] {
        assert!(
            !search_is_over(false, bound(end, own)),
            "a failure to start, a pipe error or a bad exit is the proof's failure"
        );
    }
}

#[test]
fn the_log_is_asked_after_a_refusal_only_while_the_search_has_time_left() {
    let end = Instant::now() + Duration::from_secs(60);
    let second = Duration::from_secs(1);
    assert!(may_ask_the_log(end - second, end));
    assert!(
        !may_ask_the_log(end, end),
        "a refusal that returns at the end has no query left"
    );
    assert!(
        !may_ask_the_log(end + second, end),
        "a refusal that returns after the end is the end of the search, and no event log error"
    );
}

#[test]
fn a_query_that_the_searchs_own_end_stopped_ends_the_search_whether_it_was_cut_or_never_started() {
    // Cut at the deadline it was given, and that deadline was the window's end.
    assert!(query_ends_the_search(QueryEnd::Cut {
        by_the_deadline: true
    }));
    // The end passed between the test that allowed the query and the query, or before its program
    // could start: the same end, and not the event log's failure.
    assert!(query_ends_the_search(QueryEnd::DeadlinePassed));
}

#[test]
fn a_query_that_failed_for_a_reason_of_its_own_or_ran_into_its_own_bound_does_not_end_the_search() {
    assert!(!query_ends_the_search(QueryEnd::Cut {
        by_the_deadline: false
    }));
    assert!(!query_ends_the_search(QueryEnd::Failed));
}

/// The query's own errors, as the proof's loop reads them: only an end that the search's own end
/// caused is the search's end. The platform's error values are what the proof's loop is handed.
#[cfg(windows)]
#[test]
fn each_error_of_a_query_of_the_log_is_told_apart_by_what_ended_it() {
    use kr_boundary_windows::win::applocker::Error;
    use kr_boundary_windows::win::launch::LaunchError;
    let what = "the event log query";
    assert_eq!(Error::DeadlinePassed.query_end(), QueryEnd::DeadlinePassed);
    assert_eq!(
        Error::Launch {
            what,
            source: LaunchError::DeadlinePassed,
            by_the_deadline: true
        }
        .query_end(),
        QueryEnd::DeadlinePassed
    );
    // The query's own bound passed before its program started: the search's deadline did not.
    assert_eq!(
        Error::Launch {
            what,
            source: LaunchError::DeadlinePassed,
            by_the_deadline: false
        }
        .query_end(),
        QueryEnd::Failed
    );
    assert_eq!(
        Error::TimedOut {
            what,
            by_the_deadline: true
        }
        .query_end(),
        QueryEnd::Cut {
            by_the_deadline: true
        }
    );
    assert_eq!(
        Error::TimedOut {
            what,
            by_the_deadline: false
        }
        .query_end(),
        QueryEnd::Cut {
            by_the_deadline: false
        }
    );
    assert_eq!(
        Error::Launch {
            what,
            source: LaunchError::NotStarted(5),
            by_the_deadline: true
        }
        .query_end(),
        QueryEnd::Failed
    );
    assert_eq!(
        Error::Unreadable("a bad answer".to_owned()).query_end(),
        QueryEnd::Failed
    );
}

/// A query's program that could not start because its deadline had passed ends the search only when
/// the search's own deadline set that deadline; when the query's own bound did, the query failed.
#[test]
fn a_launch_that_missed_its_deadline_ends_the_search_only_when_the_searchs_deadline_set_it() {
    assert_eq!(launch_deadline_end(true), QueryEnd::DeadlinePassed);
    assert!(query_ends_the_search(launch_deadline_end(true)));
    assert_eq!(launch_deadline_end(false), QueryEnd::Failed);
    assert!(!query_ends_the_search(launch_deadline_end(false)));
}

/// The loop's query step over a made sequence of results: each decides alone, the log that does not
/// hold the refusal yet keeps the search going, and the search's own end (a deadline before a
/// query, a deadline in a launch, a cut at the window's end) ends it, while a query's own bound and
/// every other failure fail the proof.
#[test]
fn the_loop_decides_each_query_result_of_a_made_sequence() {
    let sequence = [
        (
            QueryResult::Answered {
                refusal_found: false,
            },
            Next::Keep,
        ),
        (QueryResult::Ended(QueryEnd::DeadlinePassed), Next::Over),
        (QueryResult::Ended(launch_deadline_end(true)), Next::Over),
        (
            QueryResult::Ended(QueryEnd::Cut {
                by_the_deadline: true,
            }),
            Next::Over,
        ),
        (
            QueryResult::Ended(QueryEnd::Cut {
                by_the_deadline: false,
            }),
            Next::Fail,
        ),
        (QueryResult::Ended(launch_deadline_end(false)), Next::Fail),
        (QueryResult::Ended(QueryEnd::Failed), Next::Fail),
        (
            QueryResult::Answered {
                refusal_found: true,
            },
            Next::Found,
        ),
    ];
    for (result, next) in sequence {
        assert_eq!(next_after_a_query(result), next, "{result:?}");
    }
}
