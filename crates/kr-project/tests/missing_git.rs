//! A host without a usable Git.
//!
//! The restricted profile is prepared whether or not Git can be found, because preparing it asks
//! nothing of Git. Each invocation looks for Git first and is refused when there is none, with the
//! step that installs it. A platform that runs no Git at all, which Windows is, gives its own
//! refusal before it looks, installed or not. The cases that need no script run everywhere.

use std::ffi::{OsStr, OsString};
use std::path::Path;

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

/// Prepares a profile whose search path is `search`, inside a directory of its own.
fn profile_searching(directory: &Path, search: &Path) -> RestrictedProfile {
    RestrictedProfile::prepare_on(
        &directory.join("state"),
        environment(),
        Some(OsString::from(search)),
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
