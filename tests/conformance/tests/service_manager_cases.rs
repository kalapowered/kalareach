//! The script that runs the cases needing the account's own user service manager refuses a host
//! that has none before it asks for one, and counts a command as passed only when the cases it
//! names ran: with `--exact`, a case that was renamed is filtered out and cargo still exits 0.
//!
//! The script runs here against stand-ins for `uname`, `systemctl` and `cargo` placed first on its
//! `PATH`, so that no case runs and no service manager is asked. Each stand-in appends the
//! command it was given to one file, which a case compares with what the script must have run.
//!
//! The script has to run every case whose `ignore` reason names the user service manager: a case
//! added with such a reason that the script does not name fails here.

#![cfg(unix)]

use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use kr_conformance::rust_lex::{self, Tok};

const CRASH_CASE: &str = "a_crashed_workers_tree_is_stopped_under_the_platforms_service_manager";
const SESSION_CASE: &str =
    "a_session_in_a_service_rests_on_a_control_group_and_a_close_ends_what_left_its_tree";
const COLLECT_CASE: &str = "supervision::tests::a_transient_unit_whose_process_failed_is_collected";
const TEARDOWN_CASES: [&str; 6] = [
    "a_job_registered_for_a_tree_goes_with_it",
    "a_job_registered_for_another_environment_of_a_tree_goes_with_it",
    "a_job_registered_for_another_tree_is_left_alone",
    "a_manager_that_does_not_answer_leaves_the_trees_units_not_established_as_gone",
    "a_question_the_manager_fails_or_answers_late_is_asked_again_and_leaves_no_unit_behind",
    "a_unit_the_manager_goes_on_having_is_left_however_often_it_is_asked",
];
const PLUGIN_CASE: &str = "a_unit_the_record_does_not_hold_is_gone_when_the_world_ends_badly";
const MANAGER_ASK: &str = "systemctl --user show --property=Version --value";

/// What each stand-in does: the kernel's name the host reports, whether its user manager answers,
/// and what the test command prints and exits with.
struct Host {
    kernel: &'static str,
    manager_exit: i32,
    cargo_exit: i32,
    /// The number of cases cargo says passed, or `None` for as many as the command names after
    /// `--exact`, which is what cargo says when each name matches a case.
    cargo_passes: Option<usize>,
}

/// The shell lines of a stand-in `cargo` that prints the result line cargo prints when its cases
/// ran and passed: `passes` of them, or as many as the command names after `--exact`.
fn cargo_says(passes: Option<usize>) -> String {
    let passed = passes.map_or_else(|| "$named".to_owned(), |passes| passes.to_string());
    format!(
        "seen=0; named=0\n\
         for word in \"$@\"; do\n\
         if [ \"$seen\" = 1 ]; then named=$((named + 1)); elif [ \"$word\" = --exact ]; then seen=1; fi\n\
         done\n\
         echo \"running {passed} test\"\n\
         echo \"test result: ok. {passed} passed; 0 failed; 0 ignored; 0 measured; 33 filtered out; \
         finished in 31.20s\""
    )
}

fn a_linux_host() -> Host {
    Host {
        kernel: "Linux",
        manager_exit: 0,
        cargo_exit: 0,
        cargo_passes: None,
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
        &format!(
            "{log}\n{}\nexit {}",
            cargo_says(host.cargo_passes),
            host.cargo_exit
        ),
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

fn teardown_command() -> String {
    format!(
        "cargo test --locked -p kr-controller --test teardown_jobs -- --ignored --exact {}",
        TEARDOWN_CASES.join(" ")
    )
}

fn plugin_command() -> String {
    format!(
        "cargo test --locked -p kr-controller --test plugin_decoding -- --ignored --exact \
         {PLUGIN_CASE}"
    )
}

#[test]
fn a_host_that_is_not_linux_is_refused_before_a_service_manager_is_asked() {
    let host = Host {
        kernel: "Darwin",
        ..a_linux_host()
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
        ..a_linux_host()
    };
    let (text, code, calls) = run(&host);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("no user service manager"), "{text}");
    assert_eq!(calls, [MANAGER_ASK], "{text}");
}

#[test]
fn each_case_runs_by_its_exact_name_and_the_step_passes_when_each_passed() {
    let (text, code, calls) = run(&a_linux_host());
    assert_eq!(code, Some(0), "{text}");
    assert_eq!(
        calls,
        [
            MANAGER_ASK.to_owned(),
            test_command(CRASH_CASE),
            test_command(SESSION_CASE),
            collect_command(),
            teardown_command(),
            plugin_command()
        ],
        "{text}"
    );
}

#[test]
fn a_case_that_cargo_filtered_out_fails_the_step_although_cargo_exited_0() {
    let host = Host {
        cargo_passes: Some(0),
        ..a_linux_host()
    };
    let (text, code, calls) = run(&host);
    assert_eq!(code, Some(1), "{text}");
    assert!(
        text.contains(CRASH_CASE)
            && text.contains(SESSION_CASE)
            && text.contains(COLLECT_CASE)
            && text.contains(TEARDOWN_CASES[0])
            && text.contains(PLUGIN_CASE),
        "{text}"
    );
    assert_eq!(calls.len(), 6, "each command ran: {calls:?}");
}

/// The count the script holds a command to is the number of names it gives after `--exact`: a
/// command that names six cases and passes one fails, and the commands that name one pass.
#[test]
fn a_command_that_passed_fewer_cases_than_it_names_fails_the_step() {
    let host = Host {
        cargo_passes: Some(1),
        ..a_linux_host()
    };
    let (text, code, calls) = run(&host);
    assert_eq!(code, Some(1), "{text}");
    let said = format!(
        "did not pass the {} case(s) it names after --exact",
        TEARDOWN_CASES.len()
    );
    assert_eq!(text.matches("did not pass").count(), 1, "{text}");
    assert!(text.contains(&said), "{text}");
    assert_eq!(calls.len(), 6, "each command ran: {calls:?}");
}

#[test]
fn a_failed_case_fails_the_step_and_the_next_command_still_runs() {
    let host = Host {
        cargo_exit: 101,
        ..a_linux_host()
    };
    let (text, code, calls) = run(&host);
    assert_eq!(code, Some(1), "{text}");
    assert_eq!(calls.len(), 6, "each command ran: {calls:?}");
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
    place(dir.path(), "uname", "echo Linux");
    place(dir.path(), "systemctl", "exit 0");
    place(
        dir.path(),
        "cargo",
        &format!(
            "ls '{}' >> '{}'\n{}",
            temporary.display(),
            during.display(),
            cargo_says(None)
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
        5,
        "one file in the temporary directory while each of the five commands ran: {seen:?}"
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

/// What an `ignore` reason holds when its case starts units in the account's own user service
/// manager: the command every such case asks the manager with.
const MANAGER_REASON: &str = "systemctl --user";

/// Every `.rs` file under `directory`, leaving out build output and installed packages.
fn rust_files(directory: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        if path.is_dir() {
            if name != "target" && name != "node_modules" {
                rust_files(&path, found);
            }
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            found.push(path);
        }
    }
}

/// The functions under `root`'s `crates`, `tests` and `apps` whose `ignore` gives a reason that
/// names the user service manager, a `cfg_attr` that applies the `ignore` on one platform and a
/// reason over several lines included. A function is named by its own name, without its module.
fn cases_that_need_the_manager(root: &Path) -> BTreeSet<String> {
    let mut files = Vec::new();
    for top in ["crates", "tests", "apps"] {
        rust_files(&root.join(top), &mut files);
    }
    let mut found = BTreeSet::new();
    for file in files {
        let text = std::fs::read_to_string(&file).expect("a source file");
        if !text.contains(MANAGER_REASON) {
            continue;
        }
        let tokens = rust_lex::lex(&text).unwrap_or_else(|error| {
            panic!(
                "{} cannot be read, line {}: {}",
                file.display(),
                error.line,
                error.what
            )
        });
        for (at, token) in tokens.iter().enumerate() {
            let named = matches!(&token.tok, Tok::Ident(word) if word == "ignore")
                && matches!(
                    tokens.get(at + 1).map(|next| &next.tok),
                    Some(Tok::Punct('='))
                )
                && matches!(
                    tokens.get(at + 2).map(|next| &next.tok),
                    Some(Tok::Str(reason, _)) if reason.contains(MANAGER_REASON)
                );
            if !named {
                continue;
            }
            let after = &tokens[at + 3..];
            let function = after
                .iter()
                .position(|token| matches!(&token.tok, Tok::Ident(word) if word == "fn"));
            if let Some(Tok::Ident(name)) = function
                .and_then(|position| after.get(position + 1))
                .map(|token| &token.tok)
            {
                found.insert(name.clone());
            }
        }
    }
    found
}

/// The cases the script runs: each name that a `step` line gives after `--exact`, without its
/// module.
fn cases_the_script_runs(script: &str) -> BTreeSet<String> {
    script
        .lines()
        .filter_map(|line| line.strip_prefix("step "))
        .flat_map(|command| {
            command
                .split_whitespace()
                .skip_while(|word| *word != "--exact")
                .skip(1)
        })
        .map(|name| name.rsplit("::").next().unwrap_or(name).to_owned())
        .collect()
}

/// A repository with one source file under `crates`.
fn a_repository_with(source: &str) -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("a folder for the repository");
    let tests = root.path().join("crates/kr-example/tests");
    std::fs::create_dir_all(&tests).expect("the folder of the source");
    std::fs::write(tests.join("cases.rs"), source).expect("the source");
    root
}

fn names(cases: &[&str]) -> BTreeSet<String> {
    cases.iter().map(|case| (*case).to_owned()).collect()
}

#[test]
fn a_case_the_script_does_not_name_is_found_among_those_that_need_the_manager() {
    let root = a_repository_with(
        r##"
#[test]
#[ignore = "needs a user service manager for this account (`systemctl --user`)"]
fn a_case_that_starts_a_unit() {}

#[test]
#[ignore = "needs a device; the device lane runs it"]
fn a_case_that_needs_a_device() {}

#[test]
fn a_case_that_is_not_ignored() {
    // `systemctl --user` named in a comment is no reason.
}
"##,
    );
    let needed = cases_that_need_the_manager(root.path());
    assert_eq!(needed, names(&["a_case_that_starts_a_unit"]));

    let steps = "\
step cargo test -p kr-example --test cases -- --ignored --exact a_case_that_is_not_ignored
";
    let runs = cases_the_script_runs(steps);
    let left_out: Vec<_> = needed.difference(&runs).collect();
    assert_eq!(left_out, ["a_case_that_starts_a_unit"]);

    let steps = "\
step cargo test -p kr-example --test cases -- --ignored --exact a_case_that_is_not_ignored
step cargo test -p kr-example --test cases -- --ignored --exact m::a_case_that_starts_a_unit
";
    let runs = cases_the_script_runs(steps);
    assert!(
        needed.is_subset(&runs),
        "a name given with its module counts as its function: {runs:?}"
    );
}

#[test]
fn a_reason_over_several_lines_that_a_cfg_attr_applies_on_one_platform_is_found() {
    let root = a_repository_with(
        r##"
#[test]
#[cfg_attr(
    target_os = "linux",
    ignore = "needs a user service manager for this account (`systemctl --user`), which a \
              hosted CI runner's account does not have"
)]
fn a_case_in_the_cfg_attr_form() {}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts transient units in this account's own service manager (`systemctl --user`), \
            so an ordinary run does not run it"]
async fn an_async_case_with_the_reason_over_two_lines() {}
"##,
    );
    assert_eq!(
        cases_that_need_the_manager(root.path()),
        names(&[
            "a_case_in_the_cfg_attr_form",
            "an_async_case_with_the_reason_over_two_lines"
        ])
    );
}

/// A case ignored for want of the user service manager that the script does not run is a case no
/// train runs: the box runs the script, and nothing else asks for an ignored case there.
#[test]
fn every_case_whose_ignore_reason_names_the_user_service_manager_is_one_the_script_runs() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let needed = cases_that_need_the_manager(&root);
    assert!(
        needed.contains(SESSION_CASE),
        "the search finds the case the script was made for: {needed:?}"
    );
    let text = std::fs::read_to_string(script()).expect("the script");
    let runs = cases_the_script_runs(&text);
    let left_out: Vec<_> = needed.difference(&runs).collect();
    assert!(
        left_out.is_empty(),
        "these cases are ignored because they start units in the user service manager, and no \
         `step` line of scripts/service-manager-cases.sh names them after --exact: {left_out:?}"
    );
}
