//! A test run that names a stand-in service manager reaches no service manager of its own.
//!
//! The decisions are functions of the program, the variable's value and the installation's marker,
//! so the table cases show them in this process with files in folders of their own. A case about a
//! process whose environment or installation is the point puts its assertions in a fixture that a
//! child of the case runs, because a test program cannot change its own environment.
#![cfg(unix)]

use std::ffi::OsStr;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use kr_ipc::testing::PrivateTempDir;
use kr_ipc::testing::account_launchd::LAUNCHCTL;
use kr_ipc::testing::manager_stand_in::{
    Decision, MARKER_NAME, Marker, PROGRAM_NAME, STAND_IN_REFUSAL, VARIABLE, decide_given, held,
    held_given, marker, marker_beside, names_a_stand_in, place_installation, refusal_after,
    refused_after_given, run_fixture, substituted,
};

/// The real service manager's program, from the one helper that names it.
fn real() -> &'static Path {
    Path::new(LAUNCHCTL)
}

/// That program by its path, by its bare name, and by a path whose file name has other letter
/// case, which the file system a Mac run is on does not tell apart.
fn launchctls() -> Vec<PathBuf> {
    vec![
        real().to_path_buf(),
        PathBuf::from(real().file_name().expect("the program has a name")),
        PathBuf::from("/x/LaunchCtl"),
    ]
}

/// The canonical form of `path`, which is what a stand-in is replaced by.
fn canonical(path: &Path) -> PathBuf {
    path.canonicalize().expect("a path that exists")
}

/// A fresh folder that holds the marker and the stand-in, and the stand-in's path.
fn installation() -> (PrivateTempDir, PathBuf) {
    let folder = PrivateTempDir::create();
    let program = place_installation(folder.path());
    (folder, program)
}

/// The marker is found in the folder of the executable and in that folder's parent, and nowhere
/// else; one that cannot be read, or is not a plain file, is not an absent one.
#[test]
fn the_marker_is_found_from_the_executables_folder_and_its_parent_only() {
    let folder = PrivateTempDir::create();
    let root = folder.path();
    std::fs::create_dir_all(root.join("a/b/c")).expect("folders");
    assert_eq!(
        marker_beside(&root.join("a/b/c/kr")),
        Marker::Absent,
        "no marker anywhere"
    );

    std::fs::write(root.join("a").join(MARKER_NAME), b"").expect("a marker");
    assert_eq!(
        marker_beside(&root.join("a/b/c/kr")),
        Marker::Absent,
        "a marker two folders up belongs to no program here"
    );
    assert_eq!(
        marker_beside(&root.join("a/b/kr-daemon")),
        Marker::Beside(root.join("a")),
        "the parent of the program's folder holds the marker"
    );
    assert_eq!(
        marker_beside(&root.join("a/kr")),
        Marker::Beside(root.join("a")),
        "the program's own folder holds the marker"
    );

    std::fs::write(root.join("a/b/c").join(MARKER_NAME), b"").expect("a nearer marker");
    assert_eq!(
        marker_beside(&root.join("a/b/c/kr")),
        Marker::Beside(root.join("a/b/c"))
    );
    assert_eq!(
        marker_beside(Path::new("/")),
        Marker::Unreadable,
        "an executable with no folder reads no marker"
    );
}

/// A marker that is a folder or a link, and one in a folder that cannot be searched, is a marker
/// that cannot be read, which is a refusal and never an absent marker.
#[test]
fn a_marker_that_cannot_be_read_is_unreadable_and_never_absent() {
    let folder = PrivateTempDir::create();
    let root = folder.path();

    std::fs::create_dir_all(root.join("dir").join(MARKER_NAME)).expect("a folder as marker");
    assert_eq!(marker_beside(&root.join("dir/kr")), Marker::Unreadable);

    std::fs::write(root.join("target"), b"").expect("a file");
    std::fs::create_dir(root.join("link")).expect("a folder");
    std::os::unix::fs::symlink(root.join("target"), root.join("link").join(MARKER_NAME))
        .expect("a link as marker");
    assert_eq!(marker_beside(&root.join("link/kr")), Marker::Unreadable);

    let sealed = root.join("sealed");
    std::fs::create_dir(&sealed).expect("a folder");
    std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o000)).expect("sealed");
    let found = marker_beside(&sealed.join("kr"));
    std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o700)).expect("unsealed");
    assert_eq!(
        found,
        Marker::Unreadable,
        "a folder that cannot be searched"
    );
}

/// A program that is not `launchctl` or `systemctl` is left as it is whatever the variable and the
/// marker say.
#[test]
fn a_program_that_is_no_service_manager_is_left_alone_in_every_state() {
    let (folder, stand_in) = installation();
    for program in [
        "/usr/bin/true",
        "ioreg",
        "/usr/bin/loginctl",
        "kr-launchctl",
    ] {
        for (value, marker) in [
            (None, Marker::Absent),
            (None, Marker::Beside(folder.path().to_path_buf())),
            (None, Marker::Unreadable),
            (Some(stand_in.as_os_str()), Marker::Absent),
            (Some(OsStr::new("relative")), Marker::Absent),
            (Some(OsStr::new("")), Marker::Unreadable),
        ] {
            assert_eq!(
                decide_given(Path::new(program), value, &marker),
                Decision::Unchanged,
                "{program} with {value:?} and {marker:?}"
            );
            assert!(
                !refused_after_given(Path::new(program), value, &marker),
                "{program} with {value:?} and {marker:?}"
            );
        }
    }
}

/// With no variable and no marker nothing changes, which is what every other suite relies on.
#[test]
fn a_run_with_no_variable_and_no_marker_is_not_changed() {
    for program in launchctls().into_iter().chain([PathBuf::from("systemctl")]) {
        assert_eq!(
            decide_given(&program, None, &Marker::Absent),
            Decision::Unchanged,
            "{program:?}"
        );
        assert!(
            !refused_after_given(&program, None, &Marker::Absent),
            "{program:?}"
        );
    }
    assert!(!held_given(None, &Marker::Absent));
}

/// A marked installation with no variable, and one whose marker cannot be read, refuse every
/// command of a service-manager program, and so does the check after the substitution.
#[test]
fn a_marked_installation_with_no_variable_refuses_every_service_manager_command() {
    let (folder, _) = installation();
    for marker in [
        Marker::Beside(folder.path().to_path_buf()),
        Marker::Unreadable,
    ] {
        for program in launchctls()
            .into_iter()
            .chain([PathBuf::from("/bin/systemctl")])
        {
            assert_eq!(
                decide_given(&program, None, &marker),
                Decision::Refused,
                "{program:?} in {marker:?}"
            );
            assert!(
                refused_after_given(&program, None, &marker),
                "{program:?} in {marker:?}"
            );
        }
        assert!(held_given(None, &marker), "{marker:?}");
    }
    for program in [real(), Path::new("/bin/systemctl")] {
        assert_eq!(
            decide_given(program, Some(OsStr::new("x")), &Marker::Unreadable),
            Decision::Refused,
            "{program:?} with a variable and a marker that cannot be read"
        );
    }
}

/// A valid stand-in replaces `launchctl` and refuses `systemctl`, whose dialect it does not speak;
/// the check after the substitution refuses either real program and lets the stand-in through.
#[test]
fn a_valid_stand_in_replaces_launchctl_and_the_check_after_it_refuses_the_real_program() {
    let (folder, stand_in) = installation();
    let own = Marker::Beside(canonical(folder.path()));
    for marker in [Marker::Absent, own] {
        for program in launchctls() {
            assert_eq!(
                decide_given(&program, Some(stand_in.as_os_str()), &marker),
                Decision::Replaced(canonical(&stand_in)),
                "{program:?} in {marker:?}"
            );
            assert!(
                refused_after_given(&program, Some(stand_in.as_os_str()), &marker),
                "{program:?} stays refused after the substitution is ignored"
            );
        }
        assert_eq!(
            decide_given(
                Path::new("/bin/systemctl"),
                Some(stand_in.as_os_str()),
                &marker
            ),
            Decision::Refused,
            "the stand-in has no systemd dialect"
        );
        assert!(
            !refused_after_given(&stand_in, Some(stand_in.as_os_str()), &marker),
            "the stand-in itself is no service-manager program"
        );
        assert!(held_given(Some(stand_in.as_os_str()), &marker));
    }
}

/// A value that names no stand-in is a refusal, never a fallback to the real program: an empty or
/// relative value, a missing file, another name, a file that cannot run, a link to another file, a
/// stand-in with no marker beside it, and one that belongs to another installation than the
/// process's own.
#[test]
fn a_value_that_names_no_stand_in_is_refused_and_never_falls_back() {
    let (folder, stand_in) = installation();
    let unmarked = PrivateTempDir::create();
    std::fs::copy(&stand_in, unmarked.path().join(PROGRAM_NAME)).expect("a copy with no marker");
    std::fs::copy(&stand_in, folder.path().join("another-name")).expect("a copy by another name");
    let cannot_run = folder.path().join("cannot-run");
    std::fs::create_dir(&cannot_run).expect("a folder");
    std::fs::write(cannot_run.join(MARKER_NAME), b"").expect("a marker");
    std::fs::copy(&stand_in, cannot_run.join(PROGRAM_NAME)).expect("a copy");
    std::fs::set_permissions(
        cannot_run.join(PROGRAM_NAME),
        std::fs::Permissions::from_mode(0o600),
    )
    .expect("no execute bit");
    let linked = folder.path().join("linked");
    std::fs::create_dir(&linked).expect("a folder");
    std::fs::write(linked.join(MARKER_NAME), b"").expect("a marker");
    std::os::unix::fs::symlink("/bin/sh", linked.join(PROGRAM_NAME))
        .expect("a link to another file");
    let other = installation();
    let folder_of_a_directory = folder.path().join("directory");
    std::fs::create_dir_all(folder_of_a_directory.join(PROGRAM_NAME))
        .expect("a folder by the name");
    std::fs::write(folder_of_a_directory.join(MARKER_NAME), b"").expect("a marker");

    let named = |path: &Path| path.as_os_str().to_owned();
    let refused = [
        OsStr::new("").to_owned(),
        OsStr::new("kr-manager-stand-in").to_owned(),
        OsStr::new("./kr-manager-stand-in").to_owned(),
        named(&folder.path().join("missing").join(PROGRAM_NAME)),
        named(&folder.path().join("another-name")),
        named(&unmarked.path().join(PROGRAM_NAME)),
        named(&cannot_run.join(PROGRAM_NAME)),
        named(&linked.join(PROGRAM_NAME)),
        named(&folder_of_a_directory.join(PROGRAM_NAME)),
        named(real()),
        named(Path::new("/usr/bin/true")),
    ];
    for value in refused {
        assert_eq!(
            decide_given(real(), Some(&value), &Marker::Absent),
            Decision::Refused,
            "{value:?}"
        );
        assert!(
            refused_after_given(real(), Some(&value), &Marker::Absent),
            "{value:?}"
        );
    }
    assert_eq!(
        decide_given(
            real(),
            Some(other.1.as_os_str()),
            &Marker::Beside(canonical(folder.path()))
        ),
        Decision::Refused,
        "a stand-in of another installation than the process's own"
    );
}

/// A link whose target is the stand-in is accepted as that stand-in, by its canonical form.
#[test]
fn a_link_to_the_stand_in_is_replaced_by_the_stand_in_it_names() {
    let (folder, stand_in) = installation();
    let link = folder.path().join("link-to-the-stand-in");
    std::os::unix::fs::symlink(&stand_in, &link).expect("a link");
    assert_eq!(
        decide_given(real(), Some(link.as_os_str()), &Marker::Absent),
        Decision::Replaced(canonical(&stand_in))
    );
}

/// What a child of a case checks, with a valid stand-in named and this program unmarked.
#[test]
#[ignore = "run by a child of the case with a stand-in named"]
fn the_fixture_for_a_run_that_names_a_stand_in() {
    let stand_in = PathBuf::from(std::env::var_os(VARIABLE).expect("the child names a stand-in"));
    assert_eq!(marker(), Marker::Absent, "the child is not marked");
    assert!(held() && names_a_stand_in());
    assert_eq!(substituted(real()), Ok(canonical(&stand_in)));
    assert_eq!(refusal_after(real()), Some(STAND_IN_REFUSAL));
    assert_eq!(refusal_after(&stand_in), None);
    assert_eq!(
        substituted(Path::new("/bin/systemctl")),
        Err(STAND_IN_REFUSAL)
    );
    assert_eq!(
        substituted(Path::new("/usr/bin/true")),
        Ok(PathBuf::from("/usr/bin/true"))
    );
}

/// What a child of a case checks, with a value that names no stand-in.
#[test]
#[ignore = "run by a child of the case with a value that names no stand-in"]
fn the_fixture_for_a_run_that_names_no_stand_in() {
    assert!(std::env::var_os(VARIABLE).is_some());
    assert!(held() && !names_a_stand_in());
    assert_eq!(substituted(real()), Err(STAND_IN_REFUSAL));
    assert_eq!(refusal_after(real()), Some(STAND_IN_REFUSAL));
}

/// What a child of a case checks, with no variable and no marker.
#[test]
#[ignore = "run by a child of the case with the variable removed"]
fn the_fixture_for_a_run_that_is_not_held() {
    assert!(std::env::var_os(VARIABLE).is_none());
    assert_eq!(marker(), Marker::Absent);
    assert!(!held() && !names_a_stand_in());
    assert_eq!(substituted(real()), Ok(real().to_path_buf()));
    assert_eq!(refusal_after(real()), None);
}

/// What a child of a case checks, in a marked installation with no variable.
#[test]
#[ignore = "run by a child of the case with the variable removed, copied into a marked folder"]
fn the_fixture_for_a_marked_installation_with_no_variable() {
    assert!(std::env::var_os(VARIABLE).is_none());
    assert!(matches!(marker(), Marker::Beside(_)));
    assert!(held() && !names_a_stand_in());
    assert_eq!(substituted(real()), Err(STAND_IN_REFUSAL));
    assert_eq!(refusal_after(real()), Some(STAND_IN_REFUSAL));
}

/// What a child of a case checks, in a marked installation with a stand-in of its own named.
#[test]
#[ignore = "run by a child of the case with a stand-in named, copied into a marked folder"]
fn the_fixture_for_a_marked_installation_with_its_own_stand_in() {
    let stand_in = PathBuf::from(std::env::var_os(VARIABLE).expect("the child names a stand-in"));
    assert!(matches!(marker(), Marker::Beside(_)));
    assert!(held() && names_a_stand_in());
    assert_eq!(substituted(real()), Ok(canonical(&stand_in)));
}

/// What a child of a case checks, in a marked installation with the stand-in of another one named.
#[test]
#[ignore = "run by a child of the case with another installation's stand-in, copied into a marked folder"]
fn the_fixture_for_a_marked_installation_with_another_ones_stand_in() {
    assert!(matches!(marker(), Marker::Beside(_)));
    assert!(held() && !names_a_stand_in());
    assert_eq!(substituted(real()), Err(STAND_IN_REFUSAL));
}

/// The decisions hold in a process of its own, where they read the variable, the marker beside the
/// program, and nothing else: a run that names a stand-in, one that names none, one that is not
/// held, and the marked installations with and without the variable.
#[test]
fn the_decisions_hold_in_processes_that_read_their_own_variable_and_marker() {
    let (_folder, stand_in) = installation();
    let (_other, other_stand_in) = installation();
    let marked = PrivateTempDir::create();
    let marked_stand_in = place_installation(marked.path());
    let marked_alone = PrivateTempDir::create();
    std::fs::write(marked_alone.path().join(MARKER_NAME), b"").expect("a marker");

    let runs = [
        (
            "the_fixture_for_a_run_that_names_a_stand_in",
            Some(stand_in.as_os_str()),
            None,
        ),
        (
            "the_fixture_for_a_run_that_names_no_stand_in",
            Some(OsStr::new("kr-manager-stand-in")),
            None,
        ),
        ("the_fixture_for_a_run_that_is_not_held", None, None),
        (
            "the_fixture_for_a_marked_installation_with_no_variable",
            None,
            Some(marked_alone.path()),
        ),
        (
            "the_fixture_for_a_marked_installation_with_its_own_stand_in",
            Some(marked_stand_in.as_os_str()),
            Some(marked.path()),
        ),
        (
            "the_fixture_for_a_marked_installation_with_another_ones_stand_in",
            Some(other_stand_in.as_os_str()),
            Some(marked_alone.path()),
        ),
    ];
    for (name, value, marked_in) in runs {
        let child = run_fixture(&format!("{}::{name}", module_path!()), value, marked_in);
        assert!(child.passed, "{name}:\n{}", child.log);
    }
}
