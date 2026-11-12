//! Guest cases for the refusals of the data directory that read an entry's own handle also where no
//! manifest is listed, and for the removal that finishes what an earlier one left. They run only in
//! a disposable Windows guest, as SYSTEM, like the cases of `windows_install.rs`.

#![cfg(all(windows, feature = "testing"))]
#![allow(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

use kr_boundary_windows::manifest::{Manifest, ObjectKind};
use kr_boundary_windows::win::install::{self, DataChild, Paths};
use kr_boundary_windows::win::{acl, sd};

fn inherited_folder() -> PathBuf {
    let folder = std::env::temp_dir().join(format!(
        "krparent-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    owned_dir(&folder);
    folder
}

fn give_to(path: &Path, who: &str) {
    let done = Command::new("icacls")
        .arg(path)
        .args(["/setowner", who])
        .output()
        .unwrap();
    assert!(done.status.success(), "{done:?}");
}

fn owned_dir(path: impl AsRef<Path>) {
    std::fs::create_dir(path.as_ref()).unwrap();
    give_to(path.as_ref(), "*S-1-5-32-544");
}

fn owned_file(path: impl AsRef<Path>, bytes: &[u8]) {
    std::fs::write(path.as_ref(), bytes).unwrap();
    give_to(path.as_ref(), "*S-1-5-32-544");
}

fn paths_in(folder: &Path) -> Paths {
    let data = folder.join("Boundary");
    let program = folder.join("Program");
    Paths {
        git: program.join("git"),
        program_top: folder.to_owned(),
        program,
        staging: data.join("staging"),
        journal: data.join("journal"),
        run: data.join("run"),
        manifest: data.join("manifest.json"),
        prior: data.join("prior.json"),
        data,
    }
}

fn parent_of(folder: &Path) {
    acl::set_protected(
        folder,
        &sd::descriptor(sd::SdKind::DataParent, &sd::Principals::default()).unwrap(),
    )
    .unwrap();
}

/// A data directory with its manifest and its three directories, as an installation leaves it.
fn installed_data_directory(paths: &Paths) {
    let mut holds = install::make_data_directory(paths).unwrap();
    holds.protect().unwrap();
    let mut manifest = Manifest::begin();
    for path in [&paths.data, &paths.staging, &paths.journal, &paths.run] {
        manifest.record(ObjectKind::Directory, &path.display().to_string(), None);
    }
    manifest.save(&paths.manifest).unwrap();
    for which in [DataChild::Staging, DataChild::Journal, DataChild::Run] {
        holds.directory(which).unwrap();
    }
}

fn refusal(paths: &Paths) -> String {
    install::make_data_directory(paths)
        .expect_err("the directory is refused")
        .to_string()
}

fn moved_aside(text: &str) {
    assert!(text.contains("Move it aside"), "{text}");
    assert!(text.contains("out of the data directory"), "{text}");
    assert!(!text.contains("Remove "), "{text}");
    assert!(!text.contains("Correct what the reason names"), "{text}");
}

/// With no manifest listed, the entry that the layout gives as a record is still read on its own
/// handle: a link and a file with a second name are moved out, one of the system's class is
/// removed, and what is said to stay is only what is there.
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn with_no_manifest_a_record_takes_its_remedy_from_its_own_handle() {
    if needs_the_system() {
        return;
    }
    let folder = inherited_folder();
    parent_of(&folder);
    let paths = paths_in(&folder);
    drop(install::make_data_directory(&paths).unwrap());

    // A link at the journal's name.
    let target = inherited_folder();
    let made = Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(&paths.journal)
        .arg(&target)
        .output()
        .unwrap();
    assert!(made.status.success(), "{made:?}");
    let text = refusal(&paths);
    moved_aside(&text);
    assert!(!text.contains("stay where they are"), "{text}");
    std::fs::remove_dir(&paths.journal).unwrap();

    // The earlier-state record with a second name.
    let other = folder.join("second-name.json");
    owned_file(&paths.prior, b"{}");
    std::fs::hard_link(&paths.prior, &other).unwrap();
    moved_aside(&refusal(&paths));
    std::fs::remove_file(&other).unwrap();

    // The same record, one name and the administrators' own: it is removed, and nothing is said to
    // stay beside it, since no manifest is there.
    let text = refusal(&paths);
    assert!(text.contains("Remove "), "{text}");
    assert!(!text.contains("stay where they are"), "{text}");
    assert!(!text.contains("Move it aside"), "{text}");

    // A name that the layout does not give is removed.
    std::fs::remove_file(&paths.prior).unwrap();
    owned_file(paths.data.join("stray.txt"), b"x");
    let text = refusal(&paths);
    assert!(text.contains("Remove "), "{text}");
    let _ = std::fs::remove_dir_all(&target);
    let _ = std::fs::remove_dir_all(&folder);
}

/// A private root that no journal names takes its remedy from its own handle: another account's is
/// moved out, and only one that the administrators own is named to remove, with the manifest and the
/// journal said to stay. What the installation does not make is not said to be made new.
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_private_root_that_no_journal_names_takes_its_remedy_from_its_own_handle() {
    if needs_the_system() {
        return;
    }
    let folder = inherited_folder();
    parent_of(&folder);
    let paths = paths_in(&folder);
    installed_data_directory(&paths);
    let root = paths.run.join("ab".repeat(16));
    owned_dir(&root);
    give_to(&root, "*S-1-5-32-545");
    let text = refusal(&paths);
    moved_aside(&text);
    assert!(!text.contains("makes it new"), "{text}");
    give_to(&root, "*S-1-5-32-544");
    let text = refusal(&paths);
    assert!(text.contains("Remove "), "{text}");
    assert!(text.contains("stay where they are"), "{text}");
    let _ = std::fs::remove_dir_all(&folder);
}

/// A removal that was stopped between the manifest's deletion and the directory's, or whose last
/// deletion failed, leaves an empty data directory that a new installation accepts. The next
/// removal removes it and ends clean, in both of its modes, and says what is true when a program
/// still holds the directory: it is empty, a new installation accepts it, and the next removal
/// finishes it.
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn an_empty_data_directory_that_an_earlier_removal_left_is_finished_by_the_next_removal() {
    if needs_the_system() {
        return;
    }
    use std::os::windows::fs::OpenOptionsExt;
    let folder = inherited_folder();
    parent_of(&folder);
    let paths = paths_in(&folder);
    for quiet in [true, false] {
        drop(install::make_data_directory(&paths).unwrap());
        install::remove(&paths, quiet).expect("the empty directory is finished");
        assert!(!paths.data.exists(), "quiet {quiet}: the directory is gone");
    }

    // Held open for reading and writing and not for deleting: it cannot be removed, and the words
    // are those of an empty directory.
    drop(install::make_data_directory(&paths).unwrap());
    let held = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(3)
        .custom_flags(0x0200_0000)
        .open(&paths.data)
        .unwrap();
    let text = install::remove(&paths, true)
        .expect_err("the directory is held")
        .to_string();
    drop(held);
    assert!(text.contains("accepts an empty data directory"), "{text}");
    assert!(!text.contains("refuses until they are gone"), "{text}");
    install::remove(&paths, false).expect("the next removal finishes it");
    assert!(!paths.data.exists());
    let _ = std::fs::remove_dir_all(&folder);
}

/// The cases that make their folders under the temporary folder run as the system: under another
/// token the temporary folder lies in the account's profile, whose folders the account itself may
/// delete in, and the check of the folders above the trees refuses them, as it should.
fn needs_the_system() -> bool {
    if kr_boundary_windows::win::token::current_user()
        .is_ok_and(|user| user.to_text() == "S-1-5-18")
    {
        return false;
    }
    eprintln!(
        "SKIPPED: not run under this token: the case makes its folders in the system's temporary folder"
    );
    true
}
