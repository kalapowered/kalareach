//! When the proof's search for a refusal is over: a run cut by the window's own end ends the
//! search, and a run that failed at something never does before the window's end.

use std::time::{Duration, Instant};

use kr_boundary_windows::window::search_is_over;

const RESERVE: Duration = Duration::from_secs(2);

#[test]
fn a_run_cut_inside_the_reserve_before_the_end_ends_the_search() {
    let end = Instant::now() + Duration::from_secs(60);
    assert!(search_is_over(
        true,
        end - Duration::from_millis(1500),
        end,
        RESERVE
    ));
}

#[test]
fn a_run_cut_earlier_than_the_reserve_before_the_end_does_not_end_the_search() {
    let end = Instant::now() + Duration::from_secs(60);
    assert!(!search_is_over(
        true,
        end - Duration::from_secs(3),
        end,
        RESERVE
    ));
}

#[test]
fn the_reserve_itself_is_inside_and_a_moment_before_it_is_not() {
    let end = Instant::now() + Duration::from_secs(60);
    assert!(search_is_over(true, end - RESERVE, end, RESERVE));
    assert!(!search_is_over(
        true,
        end - RESERVE - Duration::from_millis(1),
        end,
        RESERVE
    ));
}

#[test]
fn a_run_that_failed_otherwise_before_the_end_is_still_a_failure() {
    let end = Instant::now() + Duration::from_secs(60);
    assert!(!search_is_over(
        false,
        end - Duration::from_millis(1500),
        end,
        RESERVE
    ));
    assert!(!search_is_over(
        false,
        end - Duration::from_secs(3),
        end,
        RESERVE
    ));
}

#[test]
fn after_the_end_every_result_ends_the_search() {
    let end = Instant::now() + Duration::from_secs(60);
    assert!(search_is_over(false, end, end, RESERVE));
    assert!(search_is_over(
        false,
        end + Duration::from_millis(1),
        end,
        RESERVE
    ));
    assert!(search_is_over(
        true,
        end + Duration::from_secs(5),
        end,
        RESERVE
    ));
}
