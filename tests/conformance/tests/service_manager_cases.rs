//! The script that runs the cases needing the account's own user service manager refuses a host
//! that has none before it asks for one, and counts a command as passed only when the cases it
//! names ran: with `--exact`, a case that was renamed is filtered out and cargo still exits 0.
//!
//! The script runs here against stand-ins for `uname`, `systemctl` and `cargo` placed first on its
//! `PATH`, so that no case runs and no service manager is asked. Each stand-in appends the
//! command it was given to one file, which a case compares with what the script must have run.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const CRASH_CASE: &str = "a_crashed_workers_tree_is_stopped_under_the_platforms_service_manager";
const SESSION_CASE: &str =
    "a_session_in_a_service_rests_on_a_control_group_and_a_close_ends_what_left_its_tree";
const COLLECT_CASE: &str = "supervision::tests::a_transient_unit_whose_process_failed_is_collected";
const MANAGER_ASK: &str = "systemctl --user show --property=Version --value";

/// What each stand-in does: the kernel's name the host reports, whether its user manager answers,
/// and what the test command prints and exits with.
struct Host {
    kernel: &'static str,
    manager_exit: i32,
    cargo_exit: i32,
    cargo_prints: String,
}

/// The result line cargo prints when `passed` cases ran and passed.
fn result(passed: usize) -> String {
    format!(
        "running {passed} test\ntest result: ok. {passed} passed; 0 failed; 0 ignored; \
         0 measured; 33 filtered out; finished in 31.20s\n"
    )
}

fn a_linux_host(cargo_prints: String) -> Host {
    Host {
        kernel: "Linux",
        manager_exit: 0,
        cargo_exit: 0,
        cargo_prints,
    }
}

fn script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/service-manager-cases.sh")
}

fn place(dir: &Path, name: &str, body: &str) {
    let file = dir.join(name);
    std::fs::write(&file, format!("#!/bin/sh\n{body}\n")).expect("a stand-in");
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).expect("its mode");
}

/// Runs the script on `host` and returns what it printed, its exit code and the commands the
/// stand-ins were given, one a line.
///
/// The script writes each command's output to a temporary file and reads it back. Each run is given
/// a target directory of its own, and the script makes nothing in it.
fn run(host: &Host) -> (String, Option<i32>, Vec<String>) {
    let dir = tempfile::tempdir().expect("a folder for the stand-ins");
    let calls = dir.path().join("calls");
    let says = dir.path().join("cargo-says");
    std::fs::write(&says, &host.cargo_prints).expect("what cargo prints");
    let log = format!("echo \"$(basename \"$0\") $*\" >> '{}'", calls.display());
    place(dir.path(), "uname", &format!("echo {}", host.kernel));
    place(
        dir.path(),
        "systemctl",
        &format!("{log}\nexit {}", host.manager_exit),
    );
    place(
        dir.path(),
        "cargo",
        &format!("{log}\ncat '{}'\nexit {}", says.display(), host.cargo_exit),
    );
    let output = Command::new("/bin/bash")
        .arg(script())
        .env("PATH", format!("{}:/usr/bin:/bin", dir.path().display()))
        .env("CARGO_TARGET_DIR", dir.path().join("target"))
        .output()
        .expect("bash runs the script");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let calls = std::fs::read_to_string(&calls)
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect();
    (text, output.status.code(), calls)
}

fn test_command(case: &str) -> String {
    format!("cargo test --locked -p kr-worker --test host -- --ignored --exact {case}")
}

fn collect_command() -> String {
    format!("cargo test --locked -p kr-controller --lib -- --ignored --exact {COLLECT_CASE}")
}

#[test]
fn a_host_that_is_not_linux_is_refused_before_a_service_manager_is_asked() {
    let host = Host {
        kernel: "Darwin",
        ..a_linux_host(result(1))
    };
    let (text, code, calls) = run(&host);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("only on Linux"), "{text}");
    assert!(calls.is_empty(), "nothing was asked: {calls:?}");
}

#[test]
fn an_account_with_no_user_service_manager_fails_the_step_before_any_case_runs() {
    let host = Host {
        manager_exit: 1,
        ..a_linux_host(result(1))
    };
    let (text, code, calls) = run(&host);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("no user service manager"), "{text}");
    assert_eq!(calls, [MANAGER_ASK], "{text}");
}

#[test]
fn each_case_runs_by_its_exact_name_and_the_step_passes_when_each_passed() {
    let (text, code, calls) = run(&a_linux_host(result(1)));
    assert_eq!(code, Some(0), "{text}");
    assert_eq!(
        calls,
        [
            MANAGER_ASK.to_owned(),
            test_command(CRASH_CASE),
            test_command(SESSION_CASE),
            collect_command()
        ],
        "{text}"
    );
}

#[test]
fn a_case_that_cargo_filtered_out_fails_the_step_although_cargo_exited_0() {
    let (text, code, calls) = run(&a_linux_host(result(0)));
    assert_eq!(code, Some(1), "{text}");
    assert!(
        text.contains(CRASH_CASE) && text.contains(SESSION_CASE) && text.contains(COLLECT_CASE),
        "{text}"
    );
    assert_eq!(calls.len(), 4, "each command ran: {calls:?}");
}

#[test]
fn a_failed_case_fails_the_step_and_the_next_command_still_runs() {
    let host = Host {
        cargo_exit: 101,
        ..a_linux_host(result(1))
    };
    let (text, code, calls) = run(&host);
    assert_eq!(code, Some(1), "{text}");
    assert_eq!(calls.len(), 4, "each command ran: {calls:?}");
}

/// The script keeps what each command printed in a file `mktemp` makes in the temporary directory,
/// which is there while each command runs and gone when the script ends, and it makes nothing in
/// the target directory.
#[test]
fn the_script_keeps_its_count_in_a_temporary_file_and_removes_it_when_it_ends() {
    let dir = tempfile::tempdir().expect("a folder for the stand-ins");
    let temporary = dir.path().join("temporary");
    std::fs::create_dir(&temporary).expect("a temporary directory");
    let during = dir.path().join("during");
    let says = dir.path().join("cargo-says");
    std::fs::write(&says, result(1)).expect("what cargo prints");
    place(dir.path(), "uname", "echo Linux");
    place(dir.path(), "systemctl", "exit 0");
    place(
        dir.path(),
        "cargo",
        &format!(
            "ls '{}' >> '{}'\ncat '{}'",
            temporary.display(),
            during.display(),
            says.display()
        ),
    );
    let output = Command::new("/bin/bash")
        .arg(script())
        .env("PATH", format!("{}:/usr/bin:/bin", dir.path().display()))
        .env("TMPDIR", &temporary)
        .env("CARGO_TARGET_DIR", dir.path().join("target"))
        .output()
        .expect("bash runs the script");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(0), "{text}");
    let seen = std::fs::read_to_string(&during).unwrap_or_default();
    assert_eq!(
        seen.lines().count(),
        3,
        "one file in the temporary directory while each of the three commands ran: {seen:?}"
    );
    assert!(
        seen.lines()
            .all(|name| name.starts_with("service-manager-cases.")),
        "{seen:?}"
    );
    let left: Vec<_> = std::fs::read_dir(&temporary)
        .expect("the temporary directory")
        .collect();
    assert!(left.is_empty(), "the script removes its file: {left:?}");
    assert!(
        !dir.path().join("target").exists(),
        "the script makes nothing in the target directory"
    );
}
