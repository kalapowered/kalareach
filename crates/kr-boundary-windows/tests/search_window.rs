//! When the proof's search for a refusal is over: only a run that was cut at a deadline that the
//! window's own end set ends the search. A run's own bound, and every failure of a run (it could
//! not start, a pipe failed, it ended badly), is the proof's failure at any time, near the window's
//! end or after it.

use std::time::{Duration, Instant};

use kr_boundary_windows::window::{bound, may_ask_the_log, search_is_over};

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
