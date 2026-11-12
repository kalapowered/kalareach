//! Guest cases for the checks of every folder above the installation's two trees, up to the
//! volume's root, and for the removal's remedies at the program directory and at the places that
//! it deletes from after its inspection. They run only in a disposable Windows guest, as SYSTEM,
//! like the cases of `windows_install.rs`, one at a time (`--test-threads=1`): the removal's seam
//! is process-wide.
//!
//! No case changes the list of a folder that it did not make: the folders above the trees that it
//! made are the only ones whose lists it changes, and the system's own (the temporary folder, the
//! Windows folder, the volume's root, `ProgramData`) are only read.

#![cfg(all(windows, feature = "testing"))]
#![allow(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

use kr_boundary_windows::manifest::{Manifest, ObjectKind};
use kr_boundary_windows::win::install::{self, DataChild, Entry, Options, Paths};
use kr_boundary_windows::win::{acl, sd};

/// The users group, which stands for an ordinary account.
const USERS: &str = "*S-1-5-32-545";

/// What a case made, undone on every way out of the case, a failed assertion included, in the
/// reverse order of its making: a list that it changed goes back before the folder is removed, a
/// junction is removed and not followed, a drive letter is released.
#[derive(Default)]
struct Cleanup(Vec<Box<dyn FnOnce()>>);

impl Cleanup {
    fn undo(&mut self, action: impl FnOnce() + 'static) {
        self.0.push(Box::new(action));
    }

    /// A folder that the case made, removed with everything in it.
    fn folder(&mut self, path: &Path) {
        let path = path.to_owned();
        self.undo(move || {
            let _ = std::fs::remove_dir_all(&path);
        });
    }

    /// A junction that the case made, removed as the link and never followed.
    fn junction(&mut self, link: &Path) {
        let link = link.to_owned();
        self.undo(move || {
            let _ = std::fs::remove_dir(&link);
        });
    }

    /// A right that the case gives the users group on a folder that it made, taken away again.
    /// Drops the function that the case sets for the removal's seam if the removal did not run it.
    fn hook(&mut self) {
        self.undo(install::testing::no_hook_after_the_removal_inspects_the_data_directory);
    }

    fn grant(&mut self, folder: &Path, right: &str) {
        icacls(folder, &["/grant", &format!("{USERS}:{right}")]);
        let folder = folder.to_owned();
        self.undo(move || revoke(&folder));
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        while let Some(action) = self.0.pop() {
            action();
        }
    }
}

fn icacls(path: &Path, args: &[&str]) {
    let done = Command::new("icacls")
        .arg(path)
        .args(args)
        .output()
        .unwrap();
    assert!(done.status.success(), "{done:?}");
}

/// Takes away what was granted to the users group, and fails on nothing.
fn revoke(folder: &Path) {
    let _ = Command::new("icacls")
        .arg(folder)
        .args(["/remove:g", USERS])
        .output();
}

fn owned_dir(path: impl AsRef<Path>) {
    std::fs::create_dir(path.as_ref()).unwrap();
    icacls(path.as_ref(), &["/setowner", "*S-1-5-32-544"]);
}

/// A folder in the temporary folder, owned by the administrators and with the list that it
/// inherits. It is made by an exclusive creation, so that the guard never removes a folder that the
/// case did not make, and the guard is armed before the owner changes, so that a failure of that
/// leaves nothing.
fn inherited_folder(clean: &mut Cleanup) -> PathBuf {
    let folder = std::env::temp_dir().join(format!(
        "krancestor-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    std::fs::create_dir(&folder).unwrap();
    clean.folder(&folder);
    icacls(&folder, &["/setowner", "*S-1-5-32-544"]);
    folder
}

/// The guest holds no installation: a case whose removal reaches the service, the boot marker and
/// the policy steps would delete a service of the broker's name.
fn require_clean_guest() {
    assert!(
        matches!(install::entry(&Paths::system().unwrap()), Ok(Entry::Fresh)),
        "the guest holds an installation, or an account, a service or a directory of its names"
    );
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

fn junction(link: &Path, target: &Path) {
    let made = Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .output()
        .unwrap();
    assert!(made.status.success(), "{made:?}");
}

/// The paths of an installation whose data parent is `parent`, whose program directory is
/// `program` and whose program directory's parents are read from `top`.
fn paths_with(parent: &Path, program: &Path, top: &Path) -> Paths {
    let data = parent.join("Boundary");
    Paths {
        git: program.join("git"),
        program_top: top.to_owned(),
        program: program.to_owned(),
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
    installed_data_directory_with(paths, |_| {});
}

/// [`installed_data_directory`] with what `more` records in the manifest besides the directories.
fn installed_data_directory_with(paths: &Paths, more: impl FnOnce(&mut Manifest)) {
    let mut holds = install::make_data_directory(paths).unwrap();
    holds.protect().unwrap();
    let mut manifest = Manifest::begin();
    for path in [&paths.data, &paths.staging, &paths.journal, &paths.run] {
        manifest.record(ObjectKind::Directory, &path.display().to_string(), None);
    }
    more(&mut manifest);
    manifest.save(&paths.manifest).unwrap();
    for which in [DataChild::Staging, DataChild::Journal, DataChild::Run] {
        holds.directory(which).unwrap();
    }
}

/// A protected folder under the temporary folder as the data parent, with the program directory in
/// it and the folder itself as the top that the program directory's parents are read from.
fn data_parent_with_paths(clean: &mut Cleanup) -> (PathBuf, Paths) {
    let folder = inherited_folder(clean);
    parent_of(&folder);
    let paths = paths_with(&folder, &folder.join("Program"), &folder);
    (folder, paths)
}

fn names_the_folder_and_the_right(text: &str, folder: &Path, tree: &str) {
    assert!(
        text.contains(&format!(
            "{} is a folder above the boundary's {tree}",
            folder.display()
        )),
        "{text}"
    );
    // The identity by its account name where the system resolves it, with the identifier beside it.
    assert!(text.contains(" (S-1-5-32-545)"), "{text}");
    assert!(text.contains("delete or rename an entry in it"), "{text}");
    assert!(text.contains("Nothing was changed"), "{text}");
}

/// A folder above the data directory's parent whose list gives an ordinary account the right to
/// delete or rename in it is refused by the check, by the installation's making of the directory
/// and by the removal, and the removal deletes nothing. The same folder with the system's default
/// list, which gives no such right, passes, and so do the real folders up to the volume's root.
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_folder_above_the_data_parent_that_an_ordinary_account_may_delete_in_is_refused() {
    if needs_the_system() {
        return;
    }
    let mut clean = Cleanup::default();
    // `above` is two folders over the data parent, so that a check that read only the nearest folder
    // above would pass.
    let above = inherited_folder(&mut clean);
    let middle = above.join("Middle");
    owned_dir(&middle);
    let parent = middle.join("KalaReach");
    owned_dir(&parent);
    parent_of(&parent);
    let paths = paths_with(&parent, &parent.join("Program"), &parent);
    installed_data_directory(&paths);
    install::check_data_parent(&paths).expect("the inherited list gives no such right");
    install::check_data_parent(&Paths::system().unwrap())
        .expect("the system's default lists up to the volume's root give no such right");

    // The right to add an entry is the system's default and stays allowed.
    clean.grant(&above, "(WD,AD)");
    install::check_data_parent(&paths).expect("adding an entry is allowed");
    revoke(&above);

    clean.grant(&above, "(DC)");
    let text = install::check_data_parent(&paths)
        .expect_err("a folder above gives the right to delete in it")
        .to_string();
    names_the_folder_and_the_right(&text, &above, "data directory");
    for refusal in [
        install::make_data_directory(&paths).map(drop),
        install::remove(&paths, false),
    ] {
        let text = refusal.expect_err("refused").to_string();
        names_the_folder_and_the_right(&text, &above, "data directory");
    }
    assert!(paths.manifest.exists(), "the removal deleted nothing");
    assert!(paths.staging.exists(), "the removal deleted nothing");

    // Take the right away and the same folder passes again: the check reads the list, not the place.
    revoke(&above);
    install::check_data_parent(&paths).expect("the right is gone");
    // The other rights that the check counts, each alone: delete the folder itself, change its
    // list, take it.
    for (right, said) in [
        ("(D)", "delete it"),
        ("(WDAC)", "change its list"),
        ("(WO)", "take its ownership"),
    ] {
        clean.grant(&above, right);
        let text = install::check_data_parent(&paths)
            .expect_err("a right that replaces the folder")
            .to_string();
        assert!(text.contains("S-1-5-32-545"), "{right}: {text}");
        assert!(text.contains(said), "{right}: {text}");
        revoke(&above);
    }
}

/// The same for the folders above the folder that the program directory's parents are read from,
/// which here holds the program directory: the check begins above `program_top` and reads each
/// folder down to it. The folder that the program directory's parents are read from has the
/// installation's own protected list, as `Program Files` has the system's.
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_folder_above_the_program_top_that_an_ordinary_account_may_delete_in_is_refused() {
    if needs_the_system() {
        return;
    }
    let mut clean = Cleanup::default();
    let above = inherited_folder(&mut clean);
    let middle = above.join("Middle");
    owned_dir(&middle);
    let top = middle.join("Top");
    owned_dir(&top);
    parent_of(&top);
    let data_parent = inherited_folder(&mut clean);
    parent_of(&data_parent);
    let paths = paths_with(&data_parent, &top.join("Boundary"), &top);
    install::remove(&paths, true).expect("nothing is installed and every folder passes");

    clean.grant(&above, "(DC)");
    let text = install::remove(&paths, true)
        .expect_err("a folder above the program directory's top gives the right to delete in it")
        .to_string();
    names_the_folder_and_the_right(&text, &above, "program directory");
}

/// A link at the top of the program tree (a moved `Program Files`) is the administrator's own: the
/// walk from the top down refuses it with the words of any link above the trees, reads the real
/// sentence, and never tells to remove the link.
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_link_at_the_top_of_the_program_tree_never_says_to_remove_the_link() {
    if needs_the_system() {
        return;
    }
    let mut clean = Cleanup::default();
    let target = inherited_folder(&mut clean);
    parent_of(&target);
    let container = inherited_folder(&mut clean);
    let link = container.join("Program Files");
    junction(&link, &target);
    clean.junction(&link);
    let data_parent = inherited_folder(&mut clean);
    parent_of(&data_parent);
    let paths = paths_with(&data_parent, &link.join("Boundary"), &link);
    let text = install::remove(&paths, true)
        .expect_err("a link at the top of the program tree")
        .to_string();
    assert!(
        text.contains(&format!(
            "{} is a folder above the boundary's program directory",
            link.display()
        )),
        "{text}"
    );
    assert!(text.contains("it is a link or a mounted folder"), "{text}");
    assert!(
        text.contains("does not go through a link or a mounted folder"),
        "{text}"
    );
    assert!(text.contains("Nothing was changed"), "{text}");
    assert!(
        !text.to_lowercase().contains("remove the link"),
        "an administrator is never told to remove it: {text}"
    );
}

/// A fresh installation reads the folders above the program tree before it makes, writes or stops
/// anything, so that what it says, that nothing was changed, is true. Here the data tree passes and
/// the program tree has a folder above it that fails.
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_fresh_installation_with_a_folder_above_the_program_tree_that_fails_changes_nothing() {
    if needs_the_system() {
        return;
    }
    let mut clean = Cleanup::default();
    let above = inherited_folder(&mut clean);
    let top = above.join("Top");
    owned_dir(&top);
    parent_of(&top);
    let data_parent = inherited_folder(&mut clean);
    parent_of(&data_parent);
    let paths = paths_with(&data_parent, &top.join("Boundary"), &top);
    clean.grant(&above, "(DC)");
    let options = Options {
        payload: std::env::temp_dir(),
        person: None,
    };
    let text = install::install(&paths, &options, false)
        .expect_err("a folder above the program tree fails")
        .to_string();
    names_the_folder_and_the_right(&text, &above, "program directory");
    assert!(!paths.data.exists(), "the data directory was made");
    assert!(!paths.manifest.exists(), "a manifest was written");
    assert!(!paths.program.exists(), "the program directory was made");
}

/// A link that points nowhere at the program directory's name is refused by a fresh installation
/// before anything is made, with the link's own remedy.
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_fresh_installation_refuses_a_link_that_points_nowhere_at_the_program_directorys_name() {
    if needs_the_system() {
        return;
    }
    let mut clean = Cleanup::default();
    let (folder, paths) = data_parent_with_paths(&mut clean);
    let target = inherited_folder(&mut clean);
    junction(&paths.program, &target);
    clean.junction(&paths.program);
    std::fs::remove_dir_all(&target).unwrap();
    assert!(!paths.program.exists(), "the link points nowhere");
    let text = install::entry(&paths)
        .err()
        .expect("a link at the program directory's name")
        .to_string();
    assert!(text.contains("it is a link"), "{text}");
    assert!(
        text.contains(&format!(
            "Remove the link {} itself",
            paths.program.display()
        )),
        "{text}"
    );
    assert!(text.contains("not what it points to"), "{text}");
    // Nothing is installed, so a repair, which is refused where nothing is installed, is not promised.
    assert!(!text.contains("repair"), "{text}");
    assert!(!paths.data.exists(), "nothing was made");
    assert!(folder.exists());
}

/// A link above the data parent is refused as the link it is, and what it points to is not read.
/// The words never tell an administrator to remove the link: it is the administrator's own.
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_link_above_the_data_parent_is_refused() {
    if needs_the_system() {
        return;
    }
    let mut clean = Cleanup::default();
    let target = inherited_folder(&mut clean);
    owned_dir(target.join("KalaReach"));
    let container = inherited_folder(&mut clean);
    let link = container.join("link");
    junction(&link, &target);
    clean.junction(&link);
    let parent = link.join("KalaReach");
    let paths = paths_with(&parent, &parent.join("Program"), &parent);
    let text = install::check_data_parent(&paths)
        .expect_err("a link above")
        .to_string();
    assert!(
        text.contains(&format!(
            "{} is a folder above the boundary's data directory",
            link.display()
        )),
        "{text}"
    );
    assert!(text.contains("it is a link or a mounted folder"), "{text}");
    assert!(text.contains("Nothing was changed"), "{text}");
    assert!(
        !text.to_lowercase().contains("remove the link"),
        "an administrator is never told to remove it: {text}"
    );
}

/// A substituted drive letter is no volume's root: the folders above its target are not read, so a
/// tree reached through it is refused before anything is changed, with the letter named and the
/// real path to install on.
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_substituted_drive_letter_is_refused_with_the_letter_and_the_real_path() {
    if needs_the_system() {
        return;
    }
    let mut clean = Cleanup::default();
    let real = inherited_folder(&mut clean);
    let letter = ('D'..='Z')
        .rev()
        .map(|letter| format!("{letter}:"))
        .find(|letter| !Path::new(&format!("{letter}\\")).exists())
        .expect("a free drive letter");
    let made = Command::new("subst")
        .arg(&letter)
        .arg(&real)
        .output()
        .unwrap();
    assert!(made.status.success(), "{made:?}");
    let released = letter.clone();
    clean.undo(move || {
        let _ = Command::new("subst").arg(&released).arg("/d").output();
    });
    let parent = PathBuf::from(format!("{letter}\\ProgramData\\KalaReach"));
    let paths = paths_with(&parent, &parent.join("Program"), &parent);
    let text = install::check_data_parent(&paths)
        .expect_err("a substituted drive letter")
        .to_string();
    assert!(
        text.contains(&format!(
            "{letter}\\ is a drive letter that is not the root of its volume"
        )),
        "{text}"
    );
    assert!(
        text.contains(&real.file_name().unwrap().to_string_lossy().to_string()),
        "the real path is named: {text}"
    );
    assert!(
        text.contains("end the substitution or redirection of that letter"),
        "{text}"
    );
    assert!(text.contains("Nothing was changed"), "{text}");
}

/// A root that is not there is a volume that does not answer, and it is refused before anything is
/// changed, in both walks: a folder that is not there ends a walk, but the root is the first folder
/// of it, and a tree on a drive that is gone must not let the installation make records on another
/// volume first.
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_root_that_is_not_there_is_refused_for_its_volume_before_anything_is_changed() {
    if needs_the_system() {
        return;
    }
    require_clean_guest();
    let mut clean = Cleanup::default();
    let letter = ('D'..='Z')
        .rev()
        .map(|letter| format!("{letter}:"))
        .find(|letter| !Path::new(&format!("{letter}\\")).exists())
        .expect("a free drive letter");
    // The data walk: the data parent is on the drive that is not there.
    let parent = PathBuf::from(format!("{letter}\\ProgramData\\KalaReach"));
    let paths = paths_with(&parent, &parent.join("Program"), &parent);
    let text = install::check_data_parent(&paths)
        .expect_err("a data parent on a drive that is not there")
        .to_string();
    for needle in [
        format!("{letter}\\ is a folder above the boundary's data directory"),
        "its volume did not answer".to_owned(),
        "Nothing was changed".to_owned(),
    ] {
        assert!(text.contains(&needle), "{needle}: {text}");
    }
    assert!(!text.contains("holds it open"), "{text}");
    // The program walk: the data parent is a folder of the guest's own volume, the program
    // directory's top is on the drive that is not there, and nothing is made on the way.
    let (local, mut paths) = data_parent_with_paths(&mut clean);
    paths.program_top = PathBuf::from(format!("{letter}\\Program Files\\KalaReach"));
    paths.program = paths.program_top.join("Program");
    paths.git = paths.program.join("git");
    let entry = install::entry(&paths)
        .err()
        .expect("a program directory on a drive that is not there")
        .to_string();
    let removal = install::remove(&paths, true)
        .expect_err("a program directory on a drive that is not there")
        .to_string();
    for text in [entry, removal] {
        assert!(
            text.contains(&format!(
                "{letter}\\ is a folder above the boundary's program directory"
            )),
            "{text}"
        );
        assert!(text.contains("its volume did not answer"), "{text}");
        assert!(!text.contains("holds it open"), "{text}");
    }
    assert!(
        !paths.data.exists(),
        "no data directory was made under {}",
        local.display()
    );
}

/// A link that points nowhere at the program directory's name is a link, and gets the link's own
/// remedy. The look that follows a link found nothing there, so the check let it pass, and the
/// removal then said that the directory "was not there when the removal looked for it" and kept its
/// records, every time. Now the check refuses it, before anything is changed.
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_link_that_points_nowhere_at_the_program_directorys_name_gets_the_links_own_remedy() {
    if needs_the_system() {
        return;
    }
    let mut clean = Cleanup::default();
    let (_folder, paths) = data_parent_with_paths(&mut clean);
    installed_data_directory(&paths);
    let target = inherited_folder(&mut clean);
    junction(&paths.program, &target);
    clean.junction(&paths.program);
    std::fs::remove_dir_all(&target).unwrap();
    assert!(!paths.program.exists(), "the link points nowhere");
    let text = install::remove(&paths, false)
        .expect_err("a link at the program directory's name")
        .to_string();
    assert!(text.contains("it is a link"), "{text}");
    assert!(
        text.contains(&format!(
            "Remove the link {} itself",
            paths.program.display()
        )),
        "{text}"
    );
    assert!(text.contains("not what it points to"), "{text}");
    assert!(
        !text.contains("was not there when the removal looked"),
        "{text}"
    );
    assert!(paths.manifest.exists(), "nothing was removed");
}

/// A link inside the program directory is removed as the link itself and not what it leads to.
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_link_in_the_program_directory_is_to_be_removed_as_the_link_itself() {
    if needs_the_system() {
        return;
    }
    use kr_boundary_windows::win::fresh;
    use kr_boundary_windows::win::sd::{Principals, SdKind};
    let mut clean = Cleanup::default();
    let (_folder, paths) = data_parent_with_paths(&mut clean);
    fresh::directory_all(
        &paths.program,
        SdKind::AdminDir,
        &Principals {
            users_may_read: true,
            ..Principals::default()
        },
    )
    .unwrap();
    let target = inherited_folder(&mut clean);
    let link = paths.program.join("linked");
    junction(&link, &target);
    clean.junction(&link);
    let text = install::remove(&paths, true)
        .expect_err("a link in the program directory")
        .to_string();
    assert!(text.contains("it is a link"), "{text}");
    assert!(
        text.contains(&format!("Remove the link {} itself", link.display())),
        "{text}"
    );
    assert!(text.contains("not what it points to"), "{text}");
}

/// A `journal` and a `run` directory that were absent at the removal's inspection and are there when
/// it comes to delete are not removed: the removal says that they were not there when it looked, and
/// keeps its records. They are empty here, so that the check for unfinished work passes and the old
/// test for their existence would have removed both. The removal reaches the service, the boot
/// marker and the policy steps, which delete whatever has the broker's names: the case first checks
/// that the guest holds no installation.
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_journal_and_a_run_directory_made_after_the_inspection_are_left() {
    if needs_the_system() {
        return;
    }
    require_clean_guest();
    let mut clean = Cleanup::default();
    let (_folder, paths) = data_parent_with_paths(&mut clean);
    installed_data_directory(&paths);
    std::fs::remove_dir(&paths.journal).unwrap();
    std::fs::remove_dir(&paths.run).unwrap();
    let (journal, run) = (paths.journal.clone(), paths.run.clone());
    clean.hook();
    install::testing::after_the_removal_inspects_the_data_directory(move || {
        std::fs::create_dir(&journal).unwrap();
        std::fs::create_dir(&run).unwrap();
    });
    let text = install::remove(&paths, false)
        .expect_err("what appeared was not inspected")
        .to_string();
    for directory in [&paths.journal, &paths.run] {
        assert!(
            text.contains(&format!(
                "{} was not there when the removal looked for it",
                directory.display()
            )),
            "{text}"
        );
        assert!(directory.exists(), "{} was removed", directory.display());
    }
    assert!(text.contains("its records are kept"), "{text}");
    assert!(paths.manifest.exists());
}

/// A `staging` directory that was absent at the removal's inspection and is there when it comes to
/// make it again is not used and not deleted: the removal refuses before it changes anything, and
/// what appeared stays with its file. The case first checks that the guest holds no installation:
/// a removal that trusted the directory would go on to the service step, which deletes a service of
/// the broker's name.
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_staging_directory_made_after_the_inspection_is_left_and_named() {
    if needs_the_system() {
        return;
    }
    require_clean_guest();
    let mut clean = Cleanup::default();
    let (_folder, paths) = data_parent_with_paths(&mut clean);
    installed_data_directory(&paths);
    std::fs::remove_dir(&paths.staging).unwrap();
    let staging = paths.staging.clone();
    clean.hook();
    install::testing::after_the_removal_inspects_the_data_directory(move || {
        std::fs::create_dir(&staging).unwrap();
        std::fs::write(staging.join("keep.txt"), b"x").unwrap();
    });
    let text = install::remove(&paths, false)
        .expect_err("what appeared was not inspected")
        .to_string();
    assert!(
        text.contains(&format!(
            "{} was not there when the removal looked for it",
            paths.staging.display()
        )),
        "{text}"
    );
    assert!(text.contains("Nothing was removed"), "{text}");
    assert!(
        paths.staging.join("keep.txt").exists(),
        "what appeared stays"
    );
    assert!(paths.manifest.exists());
}

/// An earlier-state record that was not in the data directory at the removal's inspection and is
/// there when it comes to use and delete the records is not used and not deleted: it is left and
/// named, and the manifest stays with it. The manifest records the Application Identity service
/// with the start value that the installation is said to have set, and the record parses and says
/// what would change the outcome if the removal acted on it: another start value, which the removal
/// would put back, the service not running before the installation (the removal would stop it on
/// this word where it runs), and an earlier policy with a rule that the machine does not have (the
/// residue check would then report that the earlier state is not back). The case reads the
/// service's start value and whether it runs before and after the removal, and the last words say
/// that neither was put back. The removal reaches the service, the boot marker and the policy
/// steps: the case first checks that the guest holds no installation.
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_prior_record_made_after_the_inspection_is_left_and_named() {
    if needs_the_system() {
        return;
    }
    use kr_boundary_windows::manifest::{Prior, STORE_VERSION};
    use kr_boundary_windows::win::service;
    /// The Application Identity service's start value and whether it runs, as the system reports.
    fn appid_state() -> (u32, bool) {
        let appid = service::manager()
            .unwrap()
            .open("AppIDSvc")
            .unwrap()
            .expect("the guest has the Application Identity service");
        (
            appid.configuration().unwrap().0,
            appid.status().unwrap().running(),
        )
    }
    require_clean_guest();
    let mut clean = Cleanup::default();
    let (start, running) = appid_state();
    // The start value and the running state go back to what they were however the case ends: a
    // removal that used the record would have changed them, and one that ended the service would
    // leave it stopped.
    clean.undo(move || {
        let _ = Command::new("reg")
            .args([
                "add",
                r"HKLM\SYSTEM\CurrentControlSet\Services\AppIDSvc",
                "/v",
                "Start",
                "/t",
                "REG_DWORD",
                "/d",
                &start.to_string(),
                "/f",
            ])
            .output();
        if running {
            let _ = Command::new("sc").args(["start", "AppIDSvc"]).output();
        }
    });
    let (_folder, paths) = data_parent_with_paths(&mut clean);
    installed_data_directory_with(&paths, |manifest| {
        manifest.record(
            ObjectKind::AppIdentity,
            "AppIDSvc",
            Some(&format!("start={start}")),
        );
    });
    let record = Prior {
        store: STORE_VERSION,
        // Another start value than the service has, so that a removal that acted on the record
        // would put it back.
        appid_start_type: if start == 4 { 3 } else { 4 },
        appid_running: false,
        policy_xml: concat!(
            r#"<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="Enabled">"#,
            r#"<FilePathRule Id="b6a4f9d2-3a43-4d0e-9a3c-5f1f0e7a1c10" Name="earlier" Description="" "#,
            r#"UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="*"/>"#,
            r#"</Conditions></FilePathRule></RuleCollection></AppLockerPolicy>"#
        )
        .to_owned(),
    };
    let prior = paths.prior.clone();
    clean.hook();
    install::testing::after_the_removal_inspects_the_data_directory(move || {
        assert!(record.write_once(&prior).unwrap());
    });
    let text = install::remove(&paths, false)
        .expect_err("what appeared was not inspected")
        .to_string();
    assert!(
        text.contains(&format!(
            "{} was not there when the removal looked for it",
            paths.prior.display()
        )),
        "{text}"
    );
    // Neither the baseline nor the start value was used: the residue check did not run on it.
    assert!(!text.contains("the earlier state is not back"), "{text}");
    assert!(!text.contains("checking the earlier state"), "{text}");
    assert!(paths.prior.exists(), "what appeared stays");
    assert!(paths.manifest.exists(), "the manifest stays with it");
    // The service was not touched, and the last words say that it was not put back and that the next
    // removal inspects the record again.
    assert_eq!(
        appid_state(),
        (start, running),
        "the Application Identity service's start value or running state changed on a record that was not approved"
    );
    assert!(
        text.contains("start value and running state were not put back"),
        "{text}"
    );
    assert!(
        text.contains("the next removal inspects the record again"),
        "{text}"
    );
}

/// A removal where nothing is installed promises no repair and names no manifest: the program
/// directory's refusals say what to remove and nothing about a repair that makes the program files
/// again, which a repair can do only where an installation is recorded. A link that points nowhere
/// at the directory's name, and a file in it with a second name, get their remedies without those
/// words.
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_removal_where_nothing_is_installed_promises_no_repair() {
    if needs_the_system() {
        return;
    }
    use kr_boundary_windows::win::fresh;
    use kr_boundary_windows::win::sd::{Principals, SdKind};
    require_clean_guest();
    let mut clean = Cleanup::default();
    let (_folder, paths) = data_parent_with_paths(&mut clean);
    // A link that points nowhere at the program directory's name.
    let target = inherited_folder(&mut clean);
    junction(&paths.program, &target);
    clean.junction(&paths.program);
    std::fs::remove_dir_all(&target).unwrap();
    let text = install::remove(&paths, false)
        .expect_err("a link at the program directory's name")
        .to_string();
    assert!(text.contains("it is a link"), "{text}");
    assert!(
        text.contains(&format!(
            "Remove the link {} itself",
            paths.program.display()
        )),
        "{text}"
    );
    assert!(!text.contains("repair"), "{text}");
    std::fs::remove_dir(&paths.program).unwrap();
    // A file with a second name inside a program directory that is otherwise the installation's.
    fresh::directory_all(
        &paths.program,
        SdKind::AdminDir,
        &Principals {
            users_may_read: true,
            ..Principals::default()
        },
    )
    .unwrap();
    let first = paths.program.join("first.exe");
    std::fs::write(&first, b"x").unwrap();
    icacls(&first, &["/setowner", "*S-1-5-32-544"]);
    std::fs::hard_link(&first, paths.program.join("second.exe")).unwrap();
    let text = install::remove(&paths, false)
        .expect_err("a file with a second name")
        .to_string();
    assert!(text.contains("more than one name"), "{text}");
    assert!(text.contains("Remove "), "{text}");
    assert!(!text.contains("repair"), "{text}");
    assert!(!text.contains("the manifest records it"), "{text}");
}

/// A known folder that an administrator gave a network path is refused in both walks, for its
/// volume: each walk asks the volume of the folder that it opens before it reads anything else of
/// it, and a volume on another computer is not one that the installation uses. The data walk
/// refuses the share's root, and the program walk, which begins at the share's root as the program
/// directory's top, refuses it the same way, from `entry` and from the removal. The comparisons
/// that follow the volume check refuse a final path on a network share too, and the printing of a
/// network path as a person can use it is for the words alone (portable cases in
/// `remedy_ancestors.rs`); here the volume check is the first thing that says no.
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_known_folder_on_a_network_share_is_refused_in_both_walks() {
    if needs_the_system() {
        return;
    }
    require_clean_guest();
    let mut clean = Cleanup::default();
    let folder = inherited_folder(&mut clean);
    // The share's root is read over the network by the system's computer account.
    icacls(&folder, &["/grant", "*S-1-1-0:(OI)(CI)RX"]);
    let name = format!("krshare{}", &uuid::Uuid::new_v4().simple().to_string()[..6]);
    let made = Command::new("net")
        .args([
            "share",
            &format!("{name}={}", folder.display()),
            "/grant:Everyone,READ",
        ])
        .output()
        .unwrap();
    assert!(made.status.success(), "{made:?}");
    let share = name.clone();
    clean.undo(move || {
        let _ = Command::new("net")
            .args(["share", &share, "/delete", "/y"])
            .output();
    });
    let root = PathBuf::from(format!(r"\\localhost\{name}\"));
    assert!(root.exists(), "the share's root opens: {}", root.display());

    // The data walk: the data parent is a folder of the share.
    let parent = root.join("Parent");
    let paths = paths_with(&parent, &parent.join("Program"), &parent);
    let text = install::check_data_parent(&paths)
        .expect_err("a data parent on a network share")
        .to_string();
    assert!(
        text.contains("is on a volume that the installation does not use"),
        "{text}"
    );
    assert!(text.contains("the volume is on another computer"), "{text}");
    assert!(text.contains(&format!(r"\\localhost\{name}\")), "{text}");
    assert!(text.contains("Nothing was changed"), "{text}");

    // The program walk: the share's root is the program directory's top.
    let (_local, mut paths) = data_parent_with_paths(&mut clean);
    paths.program_top = root.clone();
    paths.program = root.join("Program");
    paths.git = paths.program.join("git");
    let entry = install::entry(&paths)
        .err()
        .expect("a program directory on a network share")
        .to_string();
    let removal = install::remove(&paths, true)
        .expect_err("a program directory on a network share")
        .to_string();
    for text in [entry, removal] {
        assert!(
            text.contains("is on a volume that the installation does not use"),
            "{text}"
        );
        assert!(text.contains("the volume is on another computer"), "{text}");
        assert!(text.contains(&format!(r"\\localhost\{name}\")), "{text}");
    }
}
