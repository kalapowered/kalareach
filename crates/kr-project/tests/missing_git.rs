//! A host without a usable Git.
//!
//! The restricted profile is prepared whether or not Git can be found, because preparing it asks
//! nothing of Git. Each invocation looks for Git first and is refused when there is none, with the
//! step that installs it. A platform that runs no Git at all, which Windows is, gives its own
//! refusal before it looks, installed or not. The cases that need no script run everywhere.

use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::time::Duration;

use kr_project::ProjectError;
use kr_project::git::{GitRequest, RestrictedProfile};
use kr_protocol::ids::EnvironmentId;

/// The step a refusal names, which is the one fact a person needs from it.
#[cfg(not(windows))]
fn install_step() -> &'static str {
    if cfg!(target_os = "macos") {
        "xcode-select --install"
    } else {
        "Install Git"
    }
}

fn environment() -> EnvironmentId {
    EnvironmentId::new(kr_protocol::scalars::Uuid::from_bytes([7; 16]))
}

/// Prepares a profile whose search path is `search`, inside a directory of its own, with the
/// bound a daemon keeps.
fn profile_searching(directory: &Path, search: &Path) -> RestrictedProfile {
    profile_waiting(directory, search, kr_project::git::PROBE_BOUND)
}

/// Prepares a profile whose search path is `search`, giving Git `bound` to answer.
fn profile_waiting(directory: &Path, search: &Path, bound: Duration) -> RestrictedProfile {
    RestrictedProfile::prepare_on(
        &directory.join("state"),
        environment(),
        Some(OsString::from(search)),
        bound,
    )
    .expect("a profile is prepared without asking anything of Git")
}

/// Asks the profile to run a read in `directory`, which it must refuse for lack of Git.
fn refusal_of(profile: &RestrictedProfile, directory: &Path) -> ProjectError {
    let arguments: [&OsStr; 1] = [OsStr::new("status")];
    profile
        .run(&GitRequest::read(directory, &arguments))
        .expect_err("no Git runs")
}

#[cfg(not(windows))]
fn assert_refused_for_lack_of_git(refusal: &ProjectError) {
    assert!(
        matches!(refusal, ProjectError::GitUnavailable { .. }),
        "{refusal:?}"
    );
    assert_eq!(
        refusal.code(),
        kr_protocol::error::ErrorCode::HostNotConfigured
    );
    assert!(
        refusal.to_string().contains(install_step()),
        "the refusal names the step that installs Git: {refusal}"
    );
}

/// Installing Git would change nothing here, so the refusal says what the platform cannot do and
/// names no install.
#[cfg(windows)]
fn assert_refused_for_lack_of_git(refusal: &ProjectError) {
    assert_eq!(
        refusal.code(),
        kr_protocol::error::ErrorCode::HostNotConfigured,
        "{refusal:?}"
    );
    assert!(
        !refusal.code().retry_category().permits_automatic_retry(),
        "{refusal:?}"
    );
    let said = refusal.to_string();
    assert!(said.contains("ports"), "{said}");
    assert!(!said.contains("try again"), "{said}");
}

#[test]
fn a_profile_is_prepared_where_git_is_not_installed_and_each_invocation_is_refused() {
    let directory = tempfile::tempdir().expect("a directory for this test");
    let search = directory.path().join("search");
    std::fs::create_dir(&search).expect("a search path with no Git on it");
    let profile = profile_searching(directory.path(), &search);

    assert_refused_for_lack_of_git(&profile.git().expect_err("there is no Git to return"));
    assert_refused_for_lack_of_git(&refusal_of(&profile, directory.path()));
}

#[cfg(unix)]
#[test]
fn a_git_that_exits_with_status_one_is_refused_the_same_way() {
    // What `/usr/bin/git` is on a Mac that has no developer tools: a program that asks to install
    // them and ends with status 1, whatever it is asked.
    let directory = tempfile::tempdir().expect("a directory for this test");
    let search = directory.path().join("search");
    std::fs::create_dir(&search).expect("a search path of this test's own");
    stand_in(
        &search,
        "echo 'xcode-select: note: No developer tools were found.' >&2\nexit 1",
    );
    let profile = profile_searching(directory.path(), &search);

    assert_refused_for_lack_of_git(&profile.git().expect_err("the stand-in is not Git"));
    assert_refused_for_lack_of_git(&refusal_of(&profile, directory.path()));
}

#[cfg(unix)]
#[test]
fn a_git_installed_after_the_profile_was_prepared_is_found_by_the_next_look() {
    let installed = match kr_project::git::GitProgram::discover() {
        Ok(installed) => installed,
        Err(error) => {
            println!("not exercised: this host has no Git to install later: {error}");
            return;
        }
    };
    let directory = tempfile::tempdir().expect("a directory for this test");
    let search = directory.path().join("search");
    std::fs::create_dir(&search).expect("a search path with no Git on it");
    let profile = profile_searching(directory.path(), &search);
    assert_refused_for_lack_of_git(&refusal_of(&profile, directory.path()));

    // Git arrives while the profile is held, as it does when a person follows the step the refusal
    // named. A refusal that was kept would ask for a restart.
    std::os::unix::fs::symlink(installed.program(), search.join("git"))
        .expect("Git is put on the search path");
    assert_eq!(
        profile.git().expect("the next look finds it").program(),
        installed.program()
    );
}

/// Puts a `git` that is the script `body` on `search`, replacing the one that is there.
///
/// The text is written where nothing starts it and a separate process copies it into place, so no
/// descriptor of this process is ever open on the program for writing. These cases run on threads
/// of one process beside others that start children, and a child is handed a copy of every
/// descriptor open at that moment: Linux refuses to start a program that one of them still holds
/// open for writing, and a refused start would pass for an answer.
#[cfg(unix)]
fn stand_in(search: &Path, body: &str) {
    let program = search.join("git");
    let text = search.join("git.text");
    std::fs::write(&text, format!("#!/bin/sh\n{body}\n")).expect("the stand-in's text");
    let _ = std::fs::remove_file(&program);
    kr_ipc::testing::place_program(&text, &program);
    std::fs::remove_file(&text).expect("the text goes once the stand-in is in place");
}

/// Whether a process with this identifier still exists, zombies included.
#[cfg(unix)]
fn exists(pid: &str) -> bool {
    std::process::Command::new("kill")
        .args(["-0", pid])
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Waits until `gone` holds, for no longer than a guard that only a hang reaches.
#[cfg(unix)]
fn until(what: &str, gone: impl Fn() -> bool) {
    let guard = std::time::Instant::now() + Duration::from_secs(30);
    while !gone() {
        assert!(std::time::Instant::now() < guard, "{what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(unix)]
#[test]
fn a_git_that_answers_with_more_than_a_version_and_a_directory_is_refused() {
    let directory = tempfile::tempdir().expect("a directory for this test");
    let search = directory.path().join("search");
    std::fs::create_dir(&search).expect("a search path of this test's own");
    stand_in(&search, "head -c 200000 /dev/zero | tr '\\0' x");
    let profile = profile_searching(directory.path(), &search);

    let refusal = profile.git().expect_err("that is not an answer");
    assert!(
        matches!(refusal, ProjectError::GitUnavailable { .. }),
        "{refusal:?}"
    );
    assert!(
        refusal.to_string().contains("more than"),
        "it says why: {refusal}"
    );
}

#[cfg(unix)]
#[test]
fn a_git_that_answers_without_end_is_ended_where_its_output_passes_the_limit_and_refused() {
    // A program that goes on writing is not waited out. Its output passes the limit long before
    // the bound, and it is refused for that, ended while it still runs.
    let directory = tempfile::tempdir().expect("a directory for this test");
    let search = directory.path().join("search");
    std::fs::create_dir(&search).expect("a search path of this test's own");
    stand_in(&search, "exec yes");
    // The bound is a guard only: the limit ends the look long before it, and a look that waited for
    // the bound would fail the case by saying so.
    let profile = profile_waiting(directory.path(), &search, Duration::from_secs(60));

    let refusal = profile.git().expect_err("that is not an answer either");
    assert!(
        matches!(refusal, ProjectError::GitUnavailable { .. }),
        "{refusal:?}"
    );
    assert!(
        refusal.to_string().contains("more than"),
        "it says why: {refusal}"
    );
}

#[cfg(unix)]
#[test]
fn a_git_that_passes_the_limit_and_goes_quiet_is_ended_and_refused() {
    // The output passes the limit and the program then waits without writing, so nothing but the
    // host ends it: a program that went on writing would end when the pipe closed.
    let directory = tempfile::tempdir().expect("a directory for this test");
    let search = directory.path().join("search");
    std::fs::create_dir(&search).expect("a search path of this test's own");
    let own = directory.path().join("own");
    stand_in(
        &search,
        &format!(
            "echo $$ > '{}'\nyes | head -c 200000\nexec sleep 120",
            own.display()
        ),
    );
    let profile = profile_waiting(directory.path(), &search, Duration::from_secs(20));

    let refusal = profile.git().expect_err("that is not an answer");
    assert!(
        matches!(refusal, ProjectError::GitUnavailable { .. }),
        "{refusal:?}"
    );
    assert!(
        refusal.to_string().contains("more than"),
        "it says why: {refusal}"
    );
    let pid = std::fs::read_to_string(&own)
        .expect("the stand-in started before its output passed the limit")
        .trim()
        .to_owned();
    until(
        &format!("the stand-in {pid} still runs after its output passed the limit"),
        || !exists(&pid),
    );
}

#[cfg(unix)]
#[test]
fn requests_that_arrive_together_start_one_look_between_them() {
    use std::sync::Barrier;

    const REQUESTS: usize = 8;

    // Git behind a wrapper that counts how often it is asked, and is slow enough that requests
    // which arrive together meet a look that is still under way. Looked for once, it is asked its
    // two questions once; looked for by each request it would be asked them eight times over.
    let installed = match kr_project::git::GitProgram::discover() {
        Ok(installed) => installed,
        Err(error) => {
            println!("not exercised: this host has no Git to wrap: {error}");
            return;
        }
    };
    let directory = tempfile::tempdir().expect("a directory for this test");
    let search = directory.path().join("search");
    std::fs::create_dir(&search).expect("a search path of this test's own");
    let asked = directory.path().join("asked");
    stand_in(
        &search,
        &format!(
            "echo asked >> '{}'\nsleep 0.3\nexec '{}' \"$@\"",
            asked.display(),
            installed.program().display()
        ),
    );
    let profile = profile_searching(directory.path(), &search);
    let together = Barrier::new(REQUESTS);

    let programs: Vec<usize> = std::thread::scope(|scope| {
        let looks: Vec<_> = (0..REQUESTS)
            .map(|_| {
                scope.spawn(|| {
                    together.wait();
                    let found = profile.git().expect("Git is found");
                    std::ptr::from_ref(found) as usize
                })
            })
            .collect();
        looks
            .into_iter()
            .map(|look| look.join().expect("the look ends"))
            .collect()
    });

    assert!(
        programs.windows(2).all(|pair| pair[0] == pair[1]),
        "every request is given the one program that was found"
    );
    assert_eq!(
        std::fs::read_to_string(&asked)
            .expect("the wrapper was asked")
            .lines()
            .count(),
        2,
        "Git was asked for its helper directory and its version once, for all of them"
    );
}

#[cfg(unix)]
#[test]
fn requests_that_arrive_together_share_the_refusal_of_one_look() {
    use std::sync::Barrier;

    const REQUESTS: usize = 4;

    // A Git that hangs. Each request that looked for itself would wait out the bound in its turn,
    // and the stand-in would be started once for each of them.
    let directory = tempfile::tempdir().expect("a directory for this test");
    let search = directory.path().join("search");
    std::fs::create_dir(&search).expect("a search path of this test's own");
    let started = directory.path().join("started");
    stand_in(
        &search,
        &format!("echo started >> '{}'\nexec sleep 120", started.display()),
    );
    let profile = profile_waiting(directory.path(), &search, Duration::from_secs(5));
    let together = Barrier::new(REQUESTS);

    std::thread::scope(|scope| {
        let looks: Vec<_> = (0..REQUESTS)
            .map(|_| {
                scope.spawn(|| {
                    together.wait();
                    profile.git().map(|_| ()).expect_err("no Git answers")
                })
            })
            .collect();
        for look in looks {
            let refusal = look.join().expect("the look ends");
            assert!(
                matches!(refusal, ProjectError::GitFailed { .. }),
                "a look that ran out of time is a fault that passes: {refusal:?}"
            );
        }
    });

    let starts = std::fs::read_to_string(&started)
        .expect("the stand-in was started")
        .lines()
        .count();
    assert_eq!(
        starts, 1,
        "the stand-in was started once for {REQUESTS} requests that arrived together"
    );
}

#[cfg(unix)]
#[test]
fn a_git_that_ends_first_leaves_nothing_running_and_costs_no_bound() {
    // A stand-in that starts a process of its own with the pipe the question is answered on, and
    // ends. The process it started is in its group, and the group is ended when the stand-in is
    // seen to end, so the look does not wait out the bound for a pipe that would stay open.
    let directory = tempfile::tempdir().expect("a directory for this test");
    let search = directory.path().join("search");
    std::fs::create_dir(&search).expect("a search path of this test's own");
    let child = directory.path().join("child");
    stand_in(
        &search,
        &format!("sleep 120 &\necho $! > '{}'\nexit 1", child.display()),
    );
    // A bound far longer than this case may take: a look that waited for the pipe would use it.
    let profile = profile_waiting(directory.path(), &search, Duration::from_secs(60));

    // The look is made on a thread of its own, so that a look that waits for the pipe is told apart
    // from one that does not by a guard shorter than the bound, and not by how long this case took.
    let (done, ended) = std::sync::mpsc::channel();
    let refusal = std::thread::scope(|scope| {
        scope.spawn(|| {
            let _ = done.send(profile.git().map(|_| ()).expect_err("that is not Git"));
        });
        ended
            .recv_timeout(Duration::from_secs(30))
            .expect("the look ended without waiting for the pipe a process it started still held")
    });
    assert!(
        matches!(refusal, ProjectError::GitUnavailable { .. }),
        "{refusal:?}"
    );
    assert!(
        refusal.to_string().contains("exited 1"),
        "it says what happened: {refusal}"
    );
    let pid = std::fs::read_to_string(&child)
        .expect("the stand-in started its process")
        .trim()
        .to_owned();
    until(
        &format!("process {pid} that the stand-in started still runs after the stand-in ended"),
        || !exists(&pid),
    );
}

#[cfg(unix)]
#[test]
fn a_copy_of_git_that_answers_with_more_than_it_is_asked_refuses_the_look_and_keeps_nothing() {
    // The program on the search path answers both questions. The copy of Git under the helper
    // directory it names does not: it is not a copy that answers differently, which would leave the
    // program as the one that runs, but an answer that is not one, and a look that kept the
    // program on the strength of it would keep one that cannot run Git.
    let directory = tempfile::tempdir().expect("a directory for this test");
    let search = directory.path().join("search");
    let helpers = directory.path().join("helpers");
    std::fs::create_dir(&search).expect("a search path of this test's own");
    std::fs::create_dir(&helpers).expect("a helper directory of this test's own");
    let helpers = helpers
        .canonicalize()
        .expect("the helper directory resolves");
    stand_in(
        &search,
        &format!(
            "case \"$1\" in\n--exec-path) echo '{}' ;;\n--version) echo 'git version 2.50.1' ;;\nesac",
            helpers.display()
        ),
    );
    stand_in(&helpers, "head -c 200000 /dev/zero | tr '\\0' x");
    // The bound is a guard only: the copy's answer passes the limit at once.
    let profile = profile_waiting(directory.path(), &search, Duration::from_secs(60));

    let refusal = profile
        .git()
        .expect_err("a copy that answers with more than it is asked is no answer");
    assert!(
        matches!(refusal, ProjectError::GitUnavailable { .. }),
        "{refusal:?}"
    );
    assert!(
        refusal.to_string().contains("more than"),
        "it says why: {refusal}"
    );
    assert!(
        refusal
            .to_string()
            .contains(&helpers.join("git").display().to_string()),
        "and it names the copy that did not, not the program on the search path: {refusal}"
    );

    // The copy is repaired, and the next look takes it: nothing of the refusal was kept.
    stand_in(
        &helpers,
        &format!(
            "case \"$1\" in\n--exec-path) echo '{}' ;;\n--version) echo 'git version 2.50.1' ;;\nesac",
            helpers.display()
        ),
    );
    let found = profile.git().expect("the next look finds Git");
    assert_eq!(found.executable(), helpers.join("git"));
}

/// The program on the search path, which names `helpers` as its helper directory and answers both
/// questions as a Git of an old enough date does.
#[cfg(unix)]
fn answering_program(search: &Path, helpers: &Path) {
    stand_in(
        search,
        &format!(
            "case \"$1\" in\n--exec-path) echo '{}' ;;\n--version) echo 'git version 2.50.1' ;;\nesac",
            helpers.display()
        ),
    );
}

#[cfg(unix)]
#[test]
fn a_copy_of_git_that_cannot_run_or_answers_differently_leaves_the_program_as_the_one_that_runs() {
    // The copy under the helper directory is asked whether it is the same program. One that cannot
    // run, or that reports another version, is not: the program on the search path is what runs,
    // and the look succeeds with it.
    for (name, copy) in [
        ("exits-with-status-one", "exit 1"),
        ("reports-another-version", "echo 'git version 2.49.0'"),
    ] {
        let directory = tempfile::tempdir().expect("a directory for this test");
        let search = directory.path().join("search");
        let helpers = directory.path().join("helpers");
        std::fs::create_dir(&search).expect("a search path of this test's own");
        std::fs::create_dir(&helpers).expect("a helper directory of this test's own");
        let helpers = helpers
            .canonicalize()
            .expect("the helper directory resolves");
        answering_program(&search, &helpers);
        stand_in(&helpers, copy);
        let profile = profile_searching(directory.path(), &search);

        let found = profile
            .git()
            .unwrap_or_else(|error| panic!("a copy that {name} does not refuse the look: {error}"));
        assert_eq!(
            found.executable(),
            found.program(),
            "a copy that {name} is not the program that runs"
        );
    }
}

#[cfg(unix)]
#[test]
fn a_copy_of_git_that_answers_with_too_much_refuses_the_look_whatever_it_exits_with() {
    for (name, copy) in [
        ("and exits 0", "head -c 200000 /dev/zero | tr '\\0' x"),
        (
            "and exits 1",
            "head -c 200000 /dev/zero | tr '\\0' x\nexit 1",
        ),
    ] {
        let directory = tempfile::tempdir().expect("a directory for this test");
        let search = directory.path().join("search");
        let helpers = directory.path().join("helpers");
        std::fs::create_dir(&search).expect("a search path of this test's own");
        std::fs::create_dir(&helpers).expect("a helper directory of this test's own");
        let helpers = helpers
            .canonicalize()
            .expect("the helper directory resolves");
        answering_program(&search, &helpers);
        stand_in(&helpers, copy);
        let profile = profile_searching(directory.path(), &search);

        let refusal = profile
            .git()
            .expect_err("a copy that answers with too much is no answer");
        assert!(
            refusal.to_string().contains("more than"),
            "a copy that answers with too much {name}: {refusal}"
        );
    }
}
