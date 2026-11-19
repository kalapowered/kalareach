//! A Mac test run loads nothing into the account's own launchd unless it asks.
//!
//! The decision is a function of the program, its arguments and whether the run asked, so these
//! cases show it without starting a process. A case that needs a run that did not ask puts its
//! assertions in a fixture that a child of the case runs with the variable removed, because a test
//! program cannot change its own environment.

use std::path::Path;

use kr_ipc::testing::account_launchd::{REFUSAL, VARIABLE, refusal_given};

/// A `launchctl` command that loads, starts, stops or removes a job is refused when the run did
/// not ask, a read is not, and no other program is held. Nothing is refused when the run asked, and
/// only exactly `1` asks.
#[test]
fn a_launchctl_command_that_changes_the_service_manager_is_refused_unless_the_run_asked_exactly_one()
 {
    for program in [
        "/bin/launchctl",
        "launchctl",
        "/some/folder/launchctl",
        "/bin/LaunchCtl",
    ] {
        for arguments in [
            vec!["bootstrap", "gui/501", "/x/y.plist"],
            vec!["kickstart", "-k", "gui/501/job"],
            vec!["bootout", "gui/501/job"],
            vec!["kill", "TERM", "gui/501/job"],
            vec!["load", "/x/y.plist"],
            vec!["submit", "-l", "job", "--", "/bin/sleep"],
            vec!["enable", "gui/501/job"],
            vec!["-x", "print", "gui/501"],
            vec!["--version"],
            vec![],
        ] {
            let refusal = refusal_given(false, Path::new(program), &arguments);
            assert_eq!(
                refusal,
                Some(REFUSAL),
                "{program} {arguments:?} changes the manager and the run did not ask"
            );
            assert!(
                REFUSAL.contains(VARIABLE),
                "the refusal names the variable that asks"
            );
            assert_eq!(
                refusal_given(true, Path::new(program), &arguments),
                None,
                "{program} {arguments:?} is allowed to a run that asked"
            );
        }
        for arguments in [
            vec!["print", "gui/501"],
            vec!["print", "gui/501/com.example.job"],
            vec!["list"],
            vec!["list", "com.example.job"],
        ] {
            assert_eq!(
                refusal_given(false, Path::new(program), &arguments),
                None,
                "{program} {arguments:?} only reads"
            );
        }
    }
    for (program, arguments) in [
        ("/usr/bin/systemctl", vec!["--user", "start", "x.service"]),
        ("systemctl", vec!["daemon-reload"]),
        (
            "/usr/bin/systemd-run",
            vec!["--user", "--scope", "/bin/true"],
        ),
        ("/bin/sleep", vec!["1"]),
        ("/bin/sh", vec!["-c", "launchctl bootstrap"]),
        ("schtasks.exe", vec!["/Create"]),
        ("/bin/launchctl-helper", vec!["bootstrap"]),
    ] {
        assert_eq!(
            refusal_given(false, Path::new(program), &arguments),
            None,
            "{program} is not launchctl, and the rule holds launchd alone"
        );
    }
}

/// Only a run that sets the variable to exactly `1` asks.
#[test]
fn only_a_run_that_sets_the_account_launchd_variable_to_one_asks_for_the_accounts_launchd() {
    use std::ffi::OsStr;

    use kr_ipc::testing::account_launchd::asked_given;

    assert!(asked_given(Some(OsStr::new("1"))));
    for value in ["", "0", "yes", "true", "11", " 1", "1 ", "1\n", "01"] {
        assert!(
            !asked_given(Some(OsStr::new(value))),
            "{value:?} does not ask"
        );
    }
    assert!(!asked_given(None), "no value does not ask");
}

/// What a child of the case checks, with the variable removed: the helper refuses a change and
/// starts nothing, and passes a read to the program.
#[test]
#[ignore = "run by a child of the case with the variable removed"]
#[cfg(unix)]
fn the_helper_fixture_for_a_run_that_did_not_ask() {
    assert!(
        std::env::var_os(VARIABLE).is_none(),
        "the child has the variable removed"
    );
    let folder = kr_ipc::testing::PrivateTempDir::create();
    let (program, ran) = kr_ipc::testing::account_launchd::place_fake_in(folder.path());

    let refused = kr_ipc::testing::account_launchd::launchctl_at(&program, &["bootstrap", "x"])
        .expect_err("a change is refused");
    assert_eq!(refused.kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(refused.to_string(), REFUSAL);
    assert!(!ran.exists(), "a refused change started the program");

    let read = kr_ipc::testing::account_launchd::launchctl_at(&program, &["print", "gui/501"])
        .expect("a read runs the program");
    assert!(read.status.success());
    assert!(ran.exists(), "a read did not reach the program");
}

/// The helper every test source runs `launchctl` through refuses a change of a run that did not
/// ask, without starting the program, and passes a read; and the same decision, for a run that
/// asked, lets the change reach the program.
#[test]
#[cfg(unix)]
fn the_launchctl_helper_refuses_a_change_and_passes_a_read_when_the_run_did_not_ask() {
    use kr_ipc::testing::account_launchd::{launchctl_given, run_fixture};

    let child = run_fixture(
        concat!(
            module_path!(),
            "::the_helper_fixture_for_a_run_that_did_not_ask"
        ),
        None,
    );
    assert!(
        child.passed,
        "the helper of a run that did not ask:\n{}",
        child.log
    );

    let folder = kr_ipc::testing::PrivateTempDir::create();
    let (program, ran) = kr_ipc::testing::account_launchd::place_fake_in(folder.path());
    launchctl_given(true, &program, &["bootstrap", "x"]).expect("a run that asked runs it");
    assert!(
        ran.exists(),
        "a change of a run that asked did not reach the program"
    );
}
