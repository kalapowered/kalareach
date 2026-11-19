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

/// The bytes of `needle` are in the file at `path`.
fn holds(path: &str, needle: &str) -> bool {
    let bytes =
        std::fs::read(path).unwrap_or_else(|error| panic!("{path} cannot be read: {error}"));
    bytes
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

/// A program a release ships holds neither the sentence of the refusal nor the name of the variable
/// that asks, and the programs built for the suites hold both.
///
/// The second half is what makes the first one a search that can find: a program with the
/// `testing` features carries the bytes, so a shipped program that does not is not one that was
/// searched for the wrong thing. `scripts/shipped-hold-gate.sh` builds the programs, each alone as
/// a release tree builds it and the suites' own with the feature, and names them in
/// `KR_SHIPPED_HELD` and `KR_SHIPPED_PROGRAMS`, one path to a line.
#[test]
#[ignore = "reads the programs that KR_SHIPPED_HELD and KR_SHIPPED_PROGRAMS name; scripts/shipped-hold-gate.sh builds them and runs this"]
fn a_shipped_program_holds_none_of_the_launchd_refusal() {
    let paths = |variable: &str| -> Vec<String> {
        std::env::var(variable)
            .unwrap_or_else(|_| panic!("{variable} names the programs to read"))
            .lines()
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect()
    };
    let held = paths("KR_SHIPPED_HELD");
    let shipped = paths("KR_SHIPPED_PROGRAMS");
    assert!(
        !held.is_empty() && !shipped.is_empty(),
        "programs of both kinds are named"
    );
    for program in &held {
        assert!(
            holds(program, REFUSAL),
            "{program} is built with the feature and holds no refusal, so the search cannot find one"
        );
        assert!(
            holds(program, VARIABLE),
            "{program} is built with the feature and does not hold the variable's name"
        );
    }
    for program in &shipped {
        assert!(
            !holds(program, REFUSAL),
            "{program} is a shipped program and holds the launchd refusal"
        );
        assert!(
            !holds(program, VARIABLE),
            "{program} is a shipped program and holds the name of the variable that asks"
        );
    }
}

/// What a child of the case checks, with the variable removed: a command that changes the manager
/// is not `/bin/launchctl`, and a read is.
#[test]
#[ignore = "run by a child of the case with the variable removed"]
#[cfg(unix)]
fn the_command_fixture_for_a_run_that_did_not_ask() {
    use kr_ipc::testing::account_launchd::{LAUNCHCTL, command};

    assert!(
        std::env::var_os(VARIABLE).is_none(),
        "the child has the variable removed"
    );
    let change = command(&["bootstrap", "gui/501", "/x/y.plist"]);
    assert_ne!(change.get_program(), LAUNCHCTL, "a change is refused");
    let output = command(&["bootout", "gui/501/job"])
        .output()
        .expect("the refusal runs");
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&output.stderr).trim_end(),
        REFUSAL,
        "the refusal says why"
    );
    assert_eq!(
        command(&["print", "gui/501"]).get_program(),
        LAUNCHCTL,
        "a read is run"
    );
}

/// What a child of the case checks, with the variable set to `1`: a command that changes the
/// manager is `/bin/launchctl`.
#[test]
#[ignore = "run by a child of the case with the variable set"]
#[cfg(unix)]
fn the_command_fixture_for_a_run_that_asked() {
    use kr_ipc::testing::account_launchd::{LAUNCHCTL, command};

    let change = command(&["bootstrap", "gui/501", "/x/y.plist"]);
    assert_eq!(change.get_program(), LAUNCHCTL, "a run that asked runs it");
    assert_eq!(
        change.get_args().collect::<Vec<_>>(),
        ["bootstrap", "gui/501", "/x/y.plist"]
    );
}

/// The command a test source builds for `launchctl` is the program only where the run may run it:
/// a change of a run that did not ask is a shell that says why and ends with status 1.
#[test]
#[cfg(unix)]
fn the_launchctl_command_of_a_run_that_did_not_ask_is_a_refusal_and_a_read_is_launchctl() {
    use kr_ipc::testing::account_launchd::run_fixture;

    let without = run_fixture(
        concat!(
            module_path!(),
            "::the_command_fixture_for_a_run_that_did_not_ask"
        ),
        None,
    );
    assert!(without.passed, "a run that did not ask:\n{}", without.log);
    let with = run_fixture(
        concat!(module_path!(), "::the_command_fixture_for_a_run_that_asked"),
        Some("1"),
    );
    assert!(with.passed, "a run that asked:\n{}", with.log);
}

/// What `/usr/bin/env` prints of a program started with a cleared environment that was given the
/// run's asking as `value`.
#[cfg(unix)]
fn environment_given(value: Option<&str>) -> String {
    let mut command = std::process::Command::new("/usr/bin/env");
    command.env_clear();
    kr_ipc::testing::account_launchd::pass_the_ask_from(
        &mut command,
        value.map(std::ffi::OsStr::new),
    );
    String::from_utf8_lossy(&command.output().expect("env runs").stdout).into_owned()
}

/// A program started with a cleared environment holds the run's asking exactly as the run has it,
/// and holds none when the run has none: the value is not normalised to `1`.
#[test]
#[cfg(unix)]
fn the_ask_a_run_holds_reaches_a_program_started_with_a_cleared_environment() {
    assert_eq!(
        environment_given(Some("1")).trim_end(),
        format!("{VARIABLE}=1")
    );
    assert_eq!(
        environment_given(Some("yes")).trim_end(),
        format!("{VARIABLE}=yes"),
        "the value is the run's own"
    );
    assert_eq!(
        environment_given(None),
        "",
        "a run that holds none gives none"
    );
}

/// What a child of the case checks, with the variable set to `1`: a program the started
/// environment gives starts holds it.
#[test]
#[ignore = "run by a child of the case with the variable set"]
#[cfg(unix)]
fn the_started_environment_fixture_for_a_run_that_asked() {
    let folder = kr_ipc::testing::PrivateTempDir::create();
    let environment =
        kr_ipc::testing::started_environment::StartedEnvironment::within(folder.path());
    let mut command = std::process::Command::new("/usr/bin/env");
    environment.apply(&mut command);
    let printed = String::from_utf8_lossy(&command.output().expect("env runs").stdout).into_owned();
    assert!(
        printed.lines().any(|line| line == format!("{VARIABLE}=1")),
        "the started program does not hold the run's asking: {printed}"
    );
}

/// The environment a test gives the program it starts carries the run's asking on to it, the
/// service definition's daemon among what it starts.
#[test]
#[cfg(unix)]
fn a_program_the_started_environment_gives_a_cleared_environment_still_holds_the_run_ask() {
    let child = kr_ipc::testing::account_launchd::run_fixture(
        concat!(
            module_path!(),
            "::the_started_environment_fixture_for_a_run_that_asked"
        ),
        Some("1"),
    );
    assert!(child.passed, "a run that asked:\n{}", child.log);
}
