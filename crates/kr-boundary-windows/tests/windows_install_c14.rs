//! Guest cases for the removal that deletes nothing in a directory that its own inspection did not
//! approve, and for the refusals that read an entry's own handle also where the layout gives no
//! name or gives another kind of object. They run only in a disposable Windows guest, as SYSTEM,
//! like the cases of `windows_install.rs`.

#![cfg(all(windows, feature = "testing"))]
#![allow(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

use kr_boundary_windows::manifest::{Manifest, ObjectKind};
use kr_boundary_windows::win::install::{self, DataChild, Paths};
use kr_boundary_windows::win::{acl, sd};

/// A folder that a case made. It is removed with everything in it, a junction in it removed and
/// not followed, when the case ends, whether it ends by passing or by a failed assertion.
struct Folder(PathBuf);

impl std::ops::Deref for Folder {
    type Target = PathBuf;

    fn deref(&self) -> &PathBuf {
        &self.0
    }
}

impl Drop for Folder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A folder in the temporary folder, owned by the administrators. It is made by an exclusive
/// creation, so that the guard never removes a folder that the case did not make, and the guard is
/// armed before the owner changes, so that a failure of that leaves nothing.
fn inherited_folder() -> Folder {
    let path = std::env::temp_dir().join(format!(
        "krparent-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    std::fs::create_dir(&path).unwrap();
    let folder = Folder(path);
    give_to(&folder.0, "*S-1-5-32-544");
    folder
}

/// Drops the function that a case set for the removal's seam and that did not run, when the case
/// ends, so that it does not run in another case.
struct NoHook;

impl Drop for NoHook {
    fn drop(&mut self) {
        install::testing::no_hook_after_the_removal_inspects_the_data_directory();
    }
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

fn junction(link: &Path, target: &Path) {
    let made = Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .output()
        .unwrap();
    assert!(made.status.success(), "{made:?}");
}

fn paths_in(folder: &Path) -> Paths {
    paths_at(folder, folder.join("Boundary"))
}

/// The program directory beside `folder`, which is also the top the program directory's parents are
/// checked from, and the data directory where `data` says.
fn paths_at(folder: &Path, data: PathBuf) -> Paths {
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

/// A directory with files in it, standing for what a link at a name would let a deletion reach. It
/// holds no manifest: a manifest that does not parse stops the removal before it deletes anything,
/// so with one the old code would pass these cases without having been tested on the deletion.
fn bait() -> Folder {
    let target = inherited_folder();
    owned_file(target.join("prior.json"), b"{}");
    owned_dir(target.join("staging"));
    owned_file(target.join("staging").join("keep.txt"), b"x");
    target
}

fn bait_is_whole(target: &Path) {
    assert!(target.join("prior.json").exists());
    assert!(target.join("staging").join("keep.txt").exists());
}

/// Where the data directory's parent was found absent, anything that is at the data directory's name
/// by the time the removal looks again was made by nobody it checked: the removal refuses, says so,
/// and deletes none of the recognised files, nor `staging` and what is under it, in either mode. The
/// directory that appears holds `prior.json` and `staging\keep.txt` and no manifest, so that code
/// which deletes by name would delete both: the case fails on such code at the files' survival.
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_directory_made_after_its_parent_was_found_absent_is_not_deleted_from() {
    if needs_the_system() {
        return;
    }
    let _hook = NoHook;
    let folder = inherited_folder();
    parent_of(&folder);
    let top = folder.join("KalaReach");
    let paths = paths_at(&folder, top.join("Boundary"));
    for quiet in [true, false] {
        let data = paths.data.clone();
        install::testing::after_the_removal_inspects_the_data_directory(move || {
            std::fs::create_dir_all(data.join("staging")).unwrap();
            std::fs::write(data.join("prior.json"), b"{}").unwrap();
            std::fs::write(data.join("staging").join("keep.txt"), b"x").unwrap();
        });
        let text = install::remove(&paths, quiet)
            .expect_err("the directory was not approved")
            .to_string();
        assert!(
            text.contains("was not there when the removal looked"),
            "{text}"
        );
        assert!(text.contains("nothing was removed"), "{text}");
        assert!(paths.prior.exists(), "quiet {quiet}");
        assert!(paths.staging.join("keep.txt").exists(), "quiet {quiet}");
        std::fs::remove_dir_all(&top).unwrap();
    }
}

/// A junction at the data directory's name, made after the parent was checked and the directory was
/// found absent, is refused the same way, and what it leads to is untouched: `prior.json` and
/// `staging\keep.txt` in the bait are the files that code which deletes by name would delete
/// through the junction.
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_junction_at_the_data_directorys_name_made_after_the_inspection_is_not_followed() {
    if needs_the_system() {
        return;
    }
    let _hook = NoHook;
    let folder = inherited_folder();
    parent_of(&folder);
    let paths = paths_in(&folder);
    let target = bait();
    let (link, to) = (paths.data.clone(), target.clone());
    install::testing::after_the_removal_inspects_the_data_directory(move || {
        junction(&link, &to);
    });
    let text = install::remove(&paths, false)
        .expect_err("the junction was not approved")
        .to_string();
    assert!(
        text.contains("was not there when the removal looked"),
        "{text}"
    );
    bait_is_whole(&target);
    std::fs::remove_dir(&paths.data).unwrap();
}

/// An empty directory that the inspection approved is removed as it is. What is put in it after the
/// inspection (a record, `staging` as a junction) is not deleted and not followed: the directory
/// stays, and the removal says it could not remove it.
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn what_is_put_in_an_approved_empty_directory_after_the_inspection_is_not_deleted() {
    if needs_the_system() {
        return;
    }
    let _hook = NoHook;
    let folder = inherited_folder();
    parent_of(&folder);
    let paths = paths_in(&folder);
    drop(install::make_data_directory(&paths).unwrap());
    let target = bait();
    let (prior, staging, to) = (paths.prior.clone(), paths.staging.clone(), target.clone());
    install::testing::after_the_removal_inspects_the_data_directory(move || {
        std::fs::write(&prior, b"{}").unwrap();
        junction(&staging, &to);
    });
    let text = install::remove(&paths, false)
        .expect_err("the directory holds something now")
        .to_string();
    assert!(text.contains("the data directory stays:"), "{text}");
    // Nothing has checked what was put in the directory, so the words say that the next removal reads
    // the first entry that it finds, and never to remove them unread.
    assert!(text.contains("run the removal again"), "{text}");
    assert!(
        text.contains("reads the first entry that it finds on its own handle"),
        "{text}"
    );
    assert!(!text.contains("remove them"), "{text}");
    assert!(paths.prior.exists());
    bait_is_whole(&target);
    std::fs::remove_dir(&paths.staging).unwrap();
}

/// A name that the layout does not give is read on its own handle before any remedy: a junction, and
/// a file of another account's, are moved aside, whether a manifest is there or not and whether the
/// name is in the data directory or in `staging`; only one that the system's class owns is removed.
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_name_that_the_layout_does_not_give_takes_its_remedy_from_its_own_handle() {
    if needs_the_system() {
        return;
    }
    let folder = inherited_folder();
    parent_of(&folder);
    let paths = paths_in(&folder);
    installed_data_directory(&paths);
    let target = bait();

    // A junction at an unlisted name, with a manifest.
    let stray = paths.data.join("stray");
    junction(&stray, &target);
    let text = refusal(&paths);
    assert!(text.contains("stray"), "{text}");
    moved_aside(&text);
    std::fs::remove_dir(&stray).unwrap();

    // A file that another account owns, and then the same file owned by the administrators.
    owned_file(&stray, b"x");
    give_to(&stray, "*S-1-5-32-545");
    moved_aside(&refusal(&paths));
    give_to(&stray, "*S-1-5-32-544");
    let text = refusal(&paths);
    assert!(text.contains("Remove "), "{text}");
    assert!(
        text.contains("the entry at the manifest's name stays where it is"),
        "{text}"
    );
    std::fs::remove_file(&stray).unwrap();

    // A junction inside `staging`.
    let inside = paths.staging.join("leftover");
    junction(&inside, &target);
    moved_aside(&refusal(&paths));
    std::fs::remove_dir(&inside).unwrap();
    bait_is_whole(&target);

    // With no manifest in the directory, the first entry is read the same way.
    let bare = inherited_folder();
    parent_of(&bare);
    let bare_paths = paths_in(&bare);
    drop(install::make_data_directory(&bare_paths).unwrap());
    junction(&bare_paths.data.join("stray"), &target);
    moved_aside(&refusal(&bare_paths));
    std::fs::remove_dir(bare_paths.data.join("stray")).unwrap();
    bait_is_whole(&target);
}

/// What the layout gives at a name is compared with what the handle shows: a directory at the
/// earlier-state record's name, and a plain file at the name of a private root that no journal names,
/// are not the installation's, though the administrators own them. Each is moved aside, not removed.
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn an_object_of_another_kind_than_the_layout_gives_at_a_name_is_moved_aside() {
    if needs_the_system() {
        return;
    }
    let folder = inherited_folder();
    parent_of(&folder);
    let paths = paths_in(&folder);
    drop(install::make_data_directory(&paths).unwrap());
    owned_dir(&paths.prior);
    let text = refusal(&paths);
    assert!(text.contains("prior.json"), "{text}");
    moved_aside(&text);
    std::fs::remove_dir(&paths.prior).unwrap();

    let folder = inherited_folder();
    parent_of(&folder);
    let paths = paths_in(&folder);
    installed_data_directory(&paths);
    owned_file(paths.run.join("ab".repeat(16)), b"x");
    moved_aside(&refusal(&paths));
}

/// The cases that make their folders under the temporary folder run as the system: under another
/// token the temporary folder lies in the account's profile, whose folders the account itself may
/// delete in, and the check of the folders above the trees refuses them, as it should.
fn needs_the_system() -> bool {
    if kr_boundary_windows::win::token::current_user()
        .is_ok_and(|user| user.to_text().unwrap() == "S-1-5-18")
    {
        return false;
    }
    eprintln!(
        "SKIPPED: not run under this token: the case makes its folders in the system's temporary folder"
    );
    true
}
