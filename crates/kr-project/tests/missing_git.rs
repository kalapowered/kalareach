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
    assert!(
        matches!(refusal, ProjectError::GitFailed { .. }),
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
    use std::os::unix::fs::PermissionsExt as _;

    // What `/usr/bin/git` is on a Mac that has no developer tools: a program that asks to install
    // them and ends with status 1, whatever it is asked.
    let directory = tempfile::tempdir().expect("a directory for this test");
    let search = directory.path().join("search");
    std::fs::create_dir(&search).expect("a search path of this test's own");
    let stand_in = search.join("git");
    std::fs::write(
        &stand_in,
        "#!/bin/sh\necho 'xcode-select: note: No developer tools were found.' >&2\nexit 1\n",
    )
    .expect("the stand-in for Git");
    std::fs::set_permissions(&stand_in, std::fs::Permissions::from_mode(0o755))
        .expect("the stand-in can run");
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

/// Puts a `git` that is the script `body` on `search`.
#[cfg(unix)]
fn stand_in(search: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt as _;

    let program = search.join("git");
    std::fs::write(&program, format!("#!/bin/sh\n{body}\n")).expect("the stand-in for Git");
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755))
        .expect("the stand-in can run");
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
fn a_git_that_never_answers_is_ended_with_what_it_started_and_refused() {
    // A stand-in that waits on something that does not come, as an installer prompt does, and
    // starts a process of its own to wait with. The bound is what ends it; the group it leads is
    // what keeps the process it started from outliving it.
    let directory = tempfile::tempdir().expect("a directory for this test");
    let search = directory.path().join("search");
    std::fs::create_dir(&search).expect("a search path of this test's own");
    let (own, child, finished) = (
        directory.path().join("own"),
        directory.path().join("child"),
        directory.path().join("finished"),
    );
    stand_in(
        &search,
        &format!(
            "echo $$ > '{}'\nsleep 120 &\necho $! > '{}'\nwait\n: > '{}'",
            own.display(),
            child.display(),
            finished.display()
        ),
    );
    let profile = profile_waiting(directory.path(), &search, Duration::from_secs(3));

    let refusal = profile
        .git()
        .expect_err("a Git that never answers is not Git");
    assert!(
        matches!(refusal, ProjectError::GitUnavailable { .. }),
        "{refusal:?}"
    );
    assert_eq!(
        refusal.code(),
        kr_protocol::error::ErrorCode::HostNotConfigured
    );
    assert!(
        refusal.to_string().contains("did not answer"),
        "it says why: {refusal}"
    );
    for named in [&own, &child] {
        let pid = std::fs::read_to_string(named)
            .expect("the stand-in started before the bound ran out")
            .trim()
            .to_owned();
        until(
            &format!("process {pid} of the stand-in still runs after it was refused"),
            || !exists(&pid),
        );
    }
    assert!(
        !finished.exists(),
        "the stand-in was ended, and did not finish by itself"
    );
    // Nothing was kept: a Git that arrives is found by the next look.
    let Ok(installed) = kr_project::git::GitProgram::discover() else {
        return;
    };
    std::fs::remove_file(search.join("git")).expect("the stand-in goes");
    std::os::unix::fs::symlink(installed.program(), search.join("git"))
        .expect("Git is put on the search path");
    assert_eq!(
        profile.git().expect("the next look finds it").program(),
        installed.program()
    );
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
fn a_git_that_answers_without_end_is_stopped_at_the_bound_and_refused() {
    let directory = tempfile::tempdir().expect("a directory for this test");
    let search = directory.path().join("search");
    std::fs::create_dir(&search).expect("a search path of this test's own");
    stand_in(&search, "exec yes");
    let profile = profile_waiting(directory.path(), &search, Duration::from_secs(1));

    let refusal = profile.git().expect_err("that is not an answer either");
    assert!(
        matches!(refusal, ProjectError::GitUnavailable { .. }),
        "{refusal:?}"
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
    let profile = profile_waiting(directory.path(), &search, Duration::from_secs(2));
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
                matches!(refusal, ProjectError::GitUnavailable { .. }),
                "{refusal:?}"
            );
        }
    });

    let starts = std::fs::read_to_string(&started)
        .expect("the stand-in was started")
        .lines()
        .count();
    assert!(
        starts < REQUESTS,
        "the stand-in was started {starts} times for {REQUESTS} requests that arrived together"
    );
}
