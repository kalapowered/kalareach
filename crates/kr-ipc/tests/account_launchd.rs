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

/// KR-REQ-03.02: a program a release ships holds neither the sentence of the refusal nor the name of
/// the variable that asks, and the programs built for the suites hold both. A shipped program that
/// held the test-only launchd refusal would refuse the person's own per-user service.
///
/// The second half is what makes the first one a search that can find: a program with the
/// `testing` features carries the bytes, so a shipped program that does not is not one that was
/// searched for the wrong thing. `scripts/shipped-hold-gate.sh` builds the programs in the release
/// profile, each alone as a release tree builds it and in the build of the whole workspace, and the
/// suites' own with the feature, and names them in `KR_SHIPPED_HELD` and `KR_SHIPPED_PROGRAMS`, one
/// path to a line.
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

/// A case stands down exactly where the platform is a Mac and the run did not ask with exactly `1`.
#[test]
fn a_run_stands_down_where_the_platform_is_a_mac_and_the_run_did_not_ask() {
    use std::ffi::OsStr;

    use kr_ipc::testing::account_launchd::stands_down_given;

    assert!(stands_down_given(None, true));
    for value in ["", "0", "yes", "11", " 1"] {
        assert!(
            stands_down_given(Some(OsStr::new(value)), true),
            "{value:?} does not ask, so a Mac stands down"
        );
    }
    assert!(!stands_down_given(Some(OsStr::new("1")), true));
    for value in [None, Some(OsStr::new("1")), Some(OsStr::new("yes"))] {
        assert!(
            !stands_down_given(value, false),
            "no other platform stands down, whatever the value ({value:?})"
        );
    }
}

/// A launch of a run that did not ask is refused on a Mac, naming the variable and the head a case
/// begins with, and is refused nowhere else.
#[test]
fn a_launch_where_the_run_did_not_ask_is_refused_on_a_mac_and_nowhere_else() {
    use std::ffi::OsStr;

    use kr_ipc::testing::account_launchd::require_given;

    let refusal =
        require_given(None, true, "a session create").expect_err("a Mac that did not ask");
    assert!(
        refusal.starts_with("a session create would load a job"),
        "{refusal}"
    );
    assert!(refusal.contains(VARIABLE), "{refusal}");
    assert!(
        refusal.contains("account_launchd::stands_down"),
        "{refusal}"
    );
    assert!(require_given(Some(OsStr::new("yes")), true, "x").is_err());
    assert!(require_given(Some(OsStr::new("1")), true, "x").is_ok());
    assert!(require_given(None, false, "x").is_ok());
}

/// The notice is one line that begins with the case's whole name and says what would have loaded a
/// job and what asks for it.
#[test]
fn the_notice_of_a_stand_down_names_the_case_and_what_would_load_and_is_one_line() {
    use kr_ipc::testing::account_launchd::notice;

    let line = notice("tests::a_case", "the service start");
    assert!(
        line.starts_with("stood down tests::a_case: the service start needs "),
        "{line}"
    );
    assert!(line.contains(VARIABLE), "{line}");
    assert!(line.ends_with('\n'), "{line:?}");
    assert_eq!(line.matches('\n').count(), 1, "{line:?}");
}

/// What a child of the case runs: a case that stands down, which only reports its own passing.
#[test]
#[ignore = "run by a child of the case"]
#[cfg(target_os = "macos")]
fn the_stood_down_fixture() {
    let _ = kr_ipc::testing::account_launchd::stands_down("a probe");
}

/// A case that stands down shows its notice, with its whole name, in a default run and in a run that
/// shows the output of passing cases, and a run that asked shows none.
#[test]
#[cfg(target_os = "macos")]
fn a_stood_down_case_shows_its_notice_in_a_default_run_and_in_one_that_shows_output() {
    use kr_ipc::testing::account_launchd::run_fixture_with;

    let fixture = concat!(module_path!(), "::the_stood_down_fixture");
    for options in [&[][..], &["--show-output"][..]] {
        let run = run_fixture_with(fixture, None, options);
        assert!(run.passed, "{options:?}: {}", run.log);
        assert!(
            run.log.contains(
                "stood down the_stood_down_fixture: a probe needs the account's own launchd"
            ),
            "{options:?}: {}",
            run.log
        );
        assert_eq!(
            run.log.matches("stood down ").count(),
            1,
            "{options:?}: {}",
            run.log
        );
    }
    let asked = run_fixture_with(fixture, Some("1"), &["--show-output"]);
    assert!(asked.passed, "{}", asked.log);
    assert!(!asked.log.contains("stood down"), "{}", asked.log);
}

/// What a child of the case runs: a launch function's guard.
#[test]
#[ignore = "run by a child of the case"]
#[cfg(target_os = "macos")]
fn the_launch_guard_fixture() {
    kr_ipc::testing::account_launchd::require("a probe");
}

/// The guard of a launch function panics, naming the variable, in a run that did not ask on a Mac,
/// and passes in one that asked.
#[test]
#[cfg(target_os = "macos")]
fn a_launch_function_of_a_run_that_did_not_ask_panics_naming_the_variable_and_passes_where_it_asked()
 {
    use kr_ipc::testing::account_launchd::run_fixture;

    let fixture = concat!(module_path!(), "::the_launch_guard_fixture");
    let refused = run_fixture(fixture, None);
    assert!(!refused.passed, "{}", refused.log);
    assert!(
        refused.log.contains("a probe would load a job"),
        "{}",
        refused.log
    );
    assert!(refused.log.contains(VARIABLE), "{}", refused.log);
    let asked = run_fixture(fixture, Some("1"));
    assert!(asked.passed, "{}", asked.log);
}

/// A program makes a session when it is `kr` and its first argument that is no option is `new`, its
/// alias `n`, or `workflow`.
#[test]
fn a_create_is_the_first_word_that_is_no_option_and_is_new_or_its_alias_or_workflow() {
    use kr_ipc::testing::account_launchd::creates_a_session;

    let kr = Path::new("/usr/local/bin/kr");
    for arguments in [
        &["new"][..],
        &["n"],
        &["workflow"],
        &["--json", "new"],
        &["--json", "n", "--headless"],
    ] {
        assert!(
            creates_a_session(kr, arguments),
            "kr {arguments:?} makes a session"
        );
    }
    for arguments in [
        &["ls"][..],
        &["close", "x"],
        &["attach", "new"],
        &[],
        &["--json"],
    ] {
        assert!(
            !creates_a_session(kr, arguments),
            "kr {arguments:?} makes none"
        );
    }
    assert!(creates_a_session(Path::new("kr.exe"), &["new"]));
    for program in ["kr-controller", "sh", "krypton"] {
        assert!(
            !creates_a_session(Path::new(program), &["new"]),
            "{program} new is not kr"
        );
    }
}

/// Shell text makes a session when it runs `kr` with that command word, and not when it only names
/// the words.
#[test]
fn a_shell_text_that_runs_kr_new_is_a_create_and_one_that_only_names_it_is_not() {
    use kr_ipc::testing::account_launchd::creates_in_text;

    for text in [
        "kr new --shell x",
        "cd /x && kr n",
        "/usr/local/bin/kr --json new",
        "kr workflow run",
    ] {
        assert!(creates_in_text(text), "{text:?} makes a session");
    }
    for text in ["echo new", "kr ls new", "krypton new", "", "kr"] {
        assert!(!creates_in_text(text), "{text:?} makes none");
    }
}

/// What a child of the case runs: each wrapper refuses a command that makes a session exactly when
/// the run did not ask, and none refuses another command.
#[test]
#[ignore = "run by a child of the case"]
#[cfg(target_os = "macos")]
fn the_wrapper_fixture_for_commands_that_make_a_session_and_commands_that_do_not() {
    use std::panic::catch_unwind;

    use kr_ipc::testing::account_launchd::{
        asked, require_for_arguments, require_for_command, require_for_text,
    };

    let kr = Path::new("kr");
    require_for_command("a probe", kr, &["ls"]);
    require_for_command("a probe", Path::new("sh"), &["new"]);
    require_for_arguments("a probe", &["--json", "close", "x"]);
    require_for_text("a probe", "echo new");
    let refused = [
        catch_unwind(|| require_for_command("a probe", Path::new("kr"), &["new"])),
        catch_unwind(|| require_for_arguments("a probe", &["--json", "n"])),
        catch_unwind(|| require_for_text("a probe", "cd /x && kr workflow run")),
    ];
    for result in refused {
        assert_eq!(
            result.is_err(),
            !asked(),
            "a wrapper refuses exactly where the run did not ask"
        );
    }
}

/// The wrappers refuse only a command that makes a session, and only where the run did not ask.
#[test]
#[cfg(target_os = "macos")]
fn the_wrappers_refuse_a_command_that_makes_a_session_and_pass_every_other() {
    use kr_ipc::testing::account_launchd::run_fixture;

    let fixture = concat!(
        module_path!(),
        "::the_wrapper_fixture_for_commands_that_make_a_session_and_commands_that_do_not"
    );
    for asked in [None, Some("1")] {
        let run = run_fixture(fixture, asked);
        assert!(run.passed, "{asked:?}: {}", run.log);
    }
}
