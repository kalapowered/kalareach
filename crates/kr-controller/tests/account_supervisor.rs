//! The supervisor a daemon chooses, on a Mac, depends on whether the run asked for the account's
//! own launchd.
//!
//! A daemon built with the `testing` feature that finds the run did not ask chooses the detached
//! process, before it reads anything of launchd, so that no job of the account's own launchd is
//! made; one that finds the run asked chooses what the shipping daemon chooses. A case that needs
//! the one run or the other puts its assertions in a fixture that a child of the case runs with
//! the variable removed or set, because a test program cannot change its own environment.

#![cfg(target_os = "macos")]

use kr_controller::supervision::{DetachedSupervisor, LaunchdSupervisor, WorkerSupervisor, detect};
use kr_ipc::testing::account_launchd::{VARIABLE, run_fixture};

/// What a child of the case checks, with the variable removed: the daemon's supervisor is the
/// detached process.
#[test]
#[ignore = "run by a child of the case with the variable removed"]
fn the_detect_fixture_for_a_run_that_did_not_ask() {
    assert!(
        std::env::var_os(VARIABLE).is_none(),
        "the child has the variable removed"
    );
    let host = kr_ipc::testing::TempHost::create();
    let chosen = detect(&host.environment(), std::path::Path::new("daemon"));
    assert_eq!(chosen.describe(), DetachedSupervisor::new().describe());
}

/// What a child of the case checks, with the variable set to `1`: the daemon's supervisor is the
/// launchd one the platform names.
#[test]
#[ignore = "run by a child of the case with the variable set"]
fn the_detect_fixture_for_a_run_that_asked() {
    assert_eq!(
        std::env::var_os(VARIABLE).as_deref(),
        Some(std::ffi::OsStr::new("1")),
        "the child has the variable set"
    );
    let host = kr_ipc::testing::TempHost::create();
    let chosen = detect(&host.environment(), std::path::Path::new("daemon"));
    assert_eq!(chosen.describe(), LaunchdSupervisor::new().describe());
}

/// A daemon of a run that did not ask for the account's own launchd gets the detached supervisor,
/// on a host whose launchd is there to be had.
#[test]
fn a_daemon_of_a_run_that_did_not_ask_gets_the_detached_supervisor() {
    // The host has launchd, so the detached choice below is the hold's, not the host's.
    assert!(
        LaunchdSupervisor::available(),
        "this host's launchd is not there to be had, so the case shows nothing"
    );
    let child = run_fixture(
        concat!(
            module_path!(),
            "::the_detect_fixture_for_a_run_that_did_not_ask"
        ),
        None,
    );
    assert!(
        child.passed,
        "the daemon of a run that did not ask:\n{}",
        child.log
    );
}

/// A daemon of a run that asked gets the launchd supervisor the platform names.
#[test]
fn a_daemon_of_a_run_that_asked_gets_the_launchd_supervisor_the_platform_names() {
    assert!(
        LaunchdSupervisor::available(),
        "this host's launchd is not there to be had, so the case shows nothing"
    );
    let child = run_fixture(
        concat!(module_path!(), "::the_detect_fixture_for_a_run_that_asked"),
        Some("1"),
    );
    assert!(
        child.passed,
        "the daemon of a run that asked:\n{}",
        child.log
    );
}
