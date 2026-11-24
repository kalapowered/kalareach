//! The seam that lets a test run put a stand-in program in the place of the service manager, so
//! that the run reaches no service manager of the account it runs in.
//!
//! A test run names its stand-in with [`VARIABLE`], and a test installation says that it holds
//! only runs of that kind with a file named [`MARKER_NAME`] beside its programs. Every program of
//! the installation finds the marker from the folder of its own executable and that folder's
//! parent, so that a process whose environment lost the variable still knows what it belongs to.
//!
//! Three runners start a service manager: the command line's, the desktop reader's and the control
//! daemon's. Each one calls [`substituted`] where it has one program to run, and then
//! [`refusal_after`] for the program it is about to start. The second call does not depend on the
//! first: a runner whose substitution is missing, skipped or ignored reaches it with the real
//! program, and it refuses. In a run that names a stand-in, or in a marked installation, every
//! command of a program whose file name is `launchctl` or `systemctl` is refused for every verb,
//! reads included; nothing falls back to the real program.
//!
//! A run that names no stand-in, in an installation that is not marked, is not changed by anything
//! here. The module compiles only with the `testing` feature, which no shipped build enables.

use std::ffi::OsStr;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use super::account_launchd::{FixtureRun, is_launchctl, run_fixture_as};

/// The variable that names the stand-in program a run puts in the place of the service manager.
pub const VARIABLE: &str = "KR_MANAGER_STAND_IN";

/// The file name of the stand-in program.
pub const PROGRAM_NAME: &str = "kr-manager-stand-in";

/// The file name of the marker that says an installation's processes reach a service manager only
/// through the stand-in. It is one constant, so that the check of the shipped programs can search
/// for its bytes.
pub const MARKER_NAME: &str = "kr-manager-stand-in.installation";

/// What a refused service-manager command says. It is one constant, so that the check of the shipped
/// programs can search for its bytes.
pub const STAND_IN_REFUSAL: &str = "this test run reaches a service manager only through its \
                                    stand-in program, and this command does not: it is refused";

/// What the folder of an executable says about the installation it belongs to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Marker {
    /// Neither the executable's folder nor that folder's parent holds a marker.
    Absent,
    /// The marker is in this folder.
    Beside(PathBuf),
    /// A marker could not be read, or what is named as one is not a plain file. Nothing is
    /// established about the installation, so every service-manager command is refused.
    Unreadable,
}

/// What [`decide_given`] says of a program.
#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    /// The program is not one this module decides, or the run names no stand-in and is not marked.
    Unchanged,
    /// The program runs as this stand-in instead.
    Replaced(PathBuf),
    /// The command is refused.
    Refused,
}

/// The marker of the installation that holds `executable`: in its folder, or in that folder's parent,
/// which is where a program of a subfolder of the installation finds it.
#[must_use]
pub fn marker_beside(executable: &Path) -> Marker {
    let Some(folder) = executable.parent() else {
        return Marker::Unreadable;
    };
    for candidate in [Some(folder), folder.parent()].into_iter().flatten() {
        match std::fs::symlink_metadata(candidate.join(MARKER_NAME)) {
            Ok(found) if found.is_file() => return Marker::Beside(candidate.to_path_buf()),
            Ok(_) => return Marker::Unreadable,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Marker::Unreadable,
        }
    }
    Marker::Absent
}

/// The marker of this process's own installation. A process whose executable cannot be named reads
/// no marker, and that is [`Marker::Unreadable`].
#[must_use]
pub fn marker() -> Marker {
    std::env::current_exe().map_or(Marker::Unreadable, |executable| marker_beside(&executable))
}

/// Whether this process's run names a stand-in as [`decide_given`] accepts one, so that it reaches
/// no service manager of the account and needs no ask for it.
#[must_use]
pub fn names_a_stand_in() -> bool {
    std::env::var_os(VARIABLE).is_some_and(|value| stand_in_named(&value, &marker()).is_some())
}

/// Whether `program` is one whose commands this module decides: its file name is `launchctl` or
/// `systemctl`, in any letter case.
#[must_use]
pub fn names_a_manager(program: &Path) -> bool {
    is_launchctl(program)
        || program
            .file_name()
            .and_then(OsStr::to_str)
            .is_some_and(|name| name.eq_ignore_ascii_case("systemctl"))
}

/// The stand-in that `value` names, when it names one: an absolute path whose canonical form (every
/// link resolved) is a runnable regular file named [`PROGRAM_NAME`], in a folder that holds the
/// marker as a plain file and, for a process that is itself marked, in the folder of its own
/// marker.
fn stand_in_named(value: &OsStr, marker: &Marker) -> Option<PathBuf> {
    let path = Path::new(value);
    if !path.is_absolute() {
        return None;
    }
    let canonical = path.canonicalize().ok()?;
    if canonical.file_name() != Some(OsStr::new(PROGRAM_NAME)) {
        return None;
    }
    let program = std::fs::metadata(&canonical).ok()?;
    if !program.is_file() || program.permissions().mode() & 0o111 == 0 {
        return None;
    }
    let folder = canonical.parent()?;
    let marked = std::fs::symlink_metadata(folder.join(MARKER_NAME)).ok()?;
    if !marked.is_file() {
        return None;
    }
    if let Marker::Beside(own) = marker
        && own.canonicalize().ok()?.as_path() != folder
    {
        return None;
    }
    Some(canonical)
}

/// What a command of `program` is given, for a process that holds `value` of [`VARIABLE`] and
/// `marker`.
///
/// 1. A program that is not `launchctl` or `systemctl` is left as it is.
/// 2. With no variable and no marker, nothing changes.
/// 3. A marker that cannot be read, and a marked installation with no variable, refuse.
/// 4. A variable must name a stand-in as [`stand_in_named`] says; any other value, empty or relative
///    or a link to another program, refuses. It never falls back to the real program.
/// 5. A `launchctl` command then runs as the stand-in; a `systemctl` command is refused, since the
///    stand-in speaks launchd's dialect only.
#[must_use]
pub fn decide_given(program: &Path, value: Option<&OsStr>, marker: &Marker) -> Decision {
    if !names_a_manager(program) {
        return Decision::Unchanged;
    }
    match (value, marker) {
        (None, Marker::Absent) => Decision::Unchanged,
        (_, Marker::Unreadable) | (None, Marker::Beside(_)) => Decision::Refused,
        (Some(value), marker) => match stand_in_named(value, marker) {
            Some(stand_in) if is_launchctl(program) => Decision::Replaced(stand_in),
            _ => Decision::Refused,
        },
    }
}

/// Whether the independent refusal stops `program`, for a process that holds `value` of [`VARIABLE`]
/// and `marker`: a service-manager program, in a run that names a stand-in or in an installation
/// that is marked or whose marker cannot be read.
#[must_use]
pub fn refused_after_given(program: &Path, value: Option<&OsStr>, marker: &Marker) -> bool {
    names_a_manager(program) && held_given(value, marker)
}

/// Whether a process that holds `value` of [`VARIABLE`] and `marker` is held to a stand-in: it names
/// one, or its installation is marked, or its marker cannot be read.
#[must_use]
pub fn held_given(value: Option<&OsStr>, marker: &Marker) -> bool {
    value.is_some() || *marker != Marker::Absent
}

/// Whether this process is held to a stand-in, as [`held_given`] says. A process that is chooses no
/// service manager of its own.
#[must_use]
pub fn held() -> bool {
    held_given(std::env::var_os(VARIABLE).as_deref(), &marker())
}

/// The program a runner starts in place of `program`, for this process.
///
/// # Errors
///
/// [`STAND_IN_REFUSAL`], when the command is refused.
pub fn substituted(program: &Path) -> Result<PathBuf, &'static str> {
    match decide_given(program, std::env::var_os(VARIABLE).as_deref(), &marker()) {
        Decision::Unchanged => Ok(program.to_path_buf()),
        Decision::Replaced(stand_in) => Ok(stand_in),
        Decision::Refused => Err(STAND_IN_REFUSAL),
    }
}

/// Why `program`, the one a runner is about to start, is refused whatever its arguments: the
/// runner's own check, after its substitution, which does not read what the substitution decided.
#[must_use]
pub fn refusal_after(program: &Path) -> Option<&'static str> {
    refused_after_given(program, std::env::var_os(VARIABLE).as_deref(), &marker())
        .then_some(STAND_IN_REFUSAL)
}

/// Places the marker in `folder` and a program named [`PROGRAM_NAME`] beside it that writes the file
/// `stood-in` into `folder` when it runs, and returns the program's path.
///
/// # Panics
///
/// Panics when a file cannot be placed.
#[must_use]
pub fn place_installation(folder: &Path) -> PathBuf {
    std::fs::write(folder.join(MARKER_NAME), b"")
        .unwrap_or_else(|error| panic!("the marker could not be written: {error}"));
    let program = folder.join(PROGRAM_NAME);
    super::place_script(&program, "#!/bin/sh\n: > \"${0%/*}/stood-in\"\n");
    program
}

/// Runs the `#[ignore]`d fixture `name` of this test program in a child of its own that has
/// [`VARIABLE`] set to `value`, or removed when there is none, and no ask for the account's own
/// launchd. With `marked_in`, the child is a copy of this test program in that folder, which has to
/// hold a marker, so that the child's installation is the marked one.
///
/// # Panics
///
/// Panics when the copy cannot be placed or the child cannot be started.
#[must_use]
pub fn run_fixture(name: &str, value: Option<&OsStr>, marked_in: Option<&Path>) -> FixtureRun {
    let own = std::env::current_exe().expect("this test program's path");
    let program = match marked_in {
        Some(folder) => {
            let copy = folder.join(own.file_name().expect("a test program has a name"));
            super::place_program(&own, &copy);
            copy
        }
        None => own,
    };
    run_fixture_as(
        &program,
        name,
        &[(super::account_launchd::VARIABLE, None), (VARIABLE, value)],
    )
}

/// What a fixture of a runner reads of its own process: the stand-in's folder, from [`VARIABLE`].
fn stand_in_folder() -> PathBuf {
    let value = std::env::var_os(VARIABLE).expect("the child holds the variable");
    Path::new(&value)
        .parent()
        .expect("a stand-in has a folder")
        .to_path_buf()
}

/// What a fixture of a runner checks in a child that holds a valid stand-in: `run` is the runner
/// given a program named `launchctl` and answers whether it started a program. The runner starts
/// the stand-in, and the program it was given is never started.
///
/// # Panics
///
/// Panics, as the child's failed assertion, when the runner started the program it was given or
/// did not start the stand-in.
pub fn assert_runner_starts_the_stand_in(run: impl FnOnce(&Path) -> bool) {
    let folder = super::PrivateTempDir::create();
    let (program, ran) = super::account_launchd::place_fake_in(folder.path());
    let stand_in = stand_in_folder();
    assert!(
        run(&program),
        "the runner did not start the stand-in for a launchctl command"
    );
    assert!(
        stand_in.join("stood-in").exists(),
        "the stand-in was not the program the runner started"
    );
    assert!(!ran.exists(), "the runner started the program it was given");
}

/// What a fixture of a runner checks in a child that holds no variable and is marked: `run` is the
/// runner given a program named `launchctl` and answers whether it started a program. It starts
/// none.
///
/// # Panics
///
/// Panics, as the child's failed assertion, when the child holds the variable or the runner started
/// a program.
pub fn assert_runner_refuses_a_marked_installation_with_no_variable(
    run: impl FnOnce(&Path) -> bool,
) {
    assert!(
        std::env::var_os(VARIABLE).is_none(),
        "the child has the variable removed"
    );
    let folder = super::PrivateTempDir::create();
    let (program, ran) = super::account_launchd::place_fake_in(folder.path());
    assert!(
        !run(&program),
        "the runner started a program in a marked installation with no variable"
    );
    assert!(!ran.exists(), "the runner started the program it was given");
}

/// What a fixture of a runner that substitutes nothing checks in a child that holds a valid
/// stand-in: `run` is the runner given a program named `launchctl` and answers whether it started
/// a program. It starts none, since the runner has no stand-in to give it and the real program is
/// refused for every verb.
///
/// # Panics
///
/// Panics, as the child's failed assertion, when the runner started a program.
pub fn assert_runner_refuses_a_manager_program_beside_a_stand_in(run: impl FnOnce(&Path) -> bool) {
    let folder = super::PrivateTempDir::create();
    let (program, ran) = super::account_launchd::place_fake_in(folder.path());
    assert!(
        !run(&program),
        "the runner started a service-manager program in a run that names a stand-in"
    );
    assert!(!ran.exists(), "the runner started the program it was given");
    assert!(
        !stand_in_folder().join("stood-in").exists(),
        "the runner started the stand-in"
    );
}
