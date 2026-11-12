//! Guest cases for the checks of every folder above the installation's two trees, up to the
//! volume's root, and for the removal's remedies at the program directory and at the places that
//! it deletes from after its inspection. They run only in a disposable Windows guest, as SYSTEM,
//! like the cases of `windows_install.rs`.

#![cfg(all(windows, feature = "testing"))]
#![allow(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

use kr_boundary_windows::manifest::{Manifest, ObjectKind};
use kr_boundary_windows::win::install::{self, DataChild, Paths};
use kr_boundary_windows::win::{acl, sd};

/// The users group, which stands for an ordinary account.
const USERS: &str = "*S-1-5-32-545";

fn inherited_folder() -> PathBuf {
    let folder = std::env::temp_dir().join(format!(
        "krancestor-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    owned_dir(&folder);
    folder
}

fn icacls(path: &Path, args: &[&str]) {
    let done = Command::new("icacls")
        .arg(path)
        .args(args)
        .output()
        .unwrap();
    assert!(done.status.success(), "{done:?}");
}

fn owned_dir(path: impl AsRef<Path>) {
    std::fs::create_dir(path.as_ref()).unwrap();
    icacls(path.as_ref(), &["/setowner", "*S-1-5-32-544"]);
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

/// The paths of an installation whose data parent is `parent` and whose program directory is
/// `parent\Program`, with `top` as the folder that the program directory's parents are read from.
fn paths_at(parent: &Path, top: &Path) -> Paths {
    let data = parent.join("Boundary");
    let program = parent.join("Program");
    Paths {
        git: program.join("git"),
        program_top: top.to_owned(),
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

fn names_the_folder_and_the_right(text: &str, folder: &Path, tree: &str) {
    assert!(
        text.contains(&format!(
            "{} is a folder above the boundary's {tree}",
            folder.display()
        )),
        "{text}"
    );
    assert!(text.contains("S-1-5-32-545"), "{text}");
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
    let above = inherited_folder();
    let parent = above.join("KalaReach");
    owned_dir(&parent);
    parent_of(&parent);
    let paths = paths_at(&parent, &parent);
    installed_data_directory(&paths);
    install::check_data_parent(&paths).expect("the inherited list gives no such right");
    install::check_data_parent(&Paths::system().unwrap())
        .expect("the system's default lists up to the volume's root give no such right");

    // The right to add an entry is the system's default and stays allowed.
    icacls(&above, &["/grant", &format!("{USERS}:(WD,AD)")]);
    install::check_data_parent(&paths).expect("adding an entry is allowed");

    icacls(&above, &["/grant", &format!("{USERS}:(DC)")]);
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
    icacls(&above, &["/remove:g", USERS]);
    install::check_data_parent(&paths).expect("the right is gone");
    for right in ["(WDAC)", "(WO)"] {
        icacls(&above, &["/grant", &format!("{USERS}:{right}")]);
        let text = install::check_data_parent(&paths)
            .expect_err("the right to change the list or to take the folder")
            .to_string();
        assert!(text.contains("S-1-5-32-545"), "{right}: {text}");
        icacls(&above, &["/remove:g", USERS]);
    }
    let _ = std::fs::remove_dir_all(&above);
}

/// The same for the folders above the folder that the program directory's parents are read from:
/// the check begins above `program_top` and reads each folder down to it.
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_folder_above_the_program_top_that_an_ordinary_account_may_delete_in_is_refused() {
    let above = inherited_folder();
    let top = above.join("Top");
    owned_dir(&top);
    let data_parent = inherited_folder();
    parent_of(&data_parent);
    let paths = paths_at(&data_parent, &top);
    install::remove(&paths, true).expect("nothing is installed and every folder passes");

    icacls(&above, &["/grant", &format!("{USERS}:(DC)")]);
    let text = install::remove(&paths, true)
        .expect_err("a folder above the program directory's top gives the right to delete in it")
        .to_string();
    names_the_folder_and_the_right(&text, &above, "program directory");
    let _ = std::fs::remove_dir_all(&above);
    let _ = std::fs::remove_dir_all(&data_parent);
}

/// A link above the data parent is refused as the link it is, and what it points to is not read.
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_link_above_the_data_parent_is_refused() {
    let target = inherited_folder();
    owned_dir(target.join("KalaReach"));
    let container = inherited_folder();
    let link = container.join("link");
    junction(&link, &target);
    let parent = link.join("KalaReach");
    let paths = paths_at(&parent, &parent);
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
    assert!(text.contains("it is a link"), "{text}");
    std::fs::remove_dir(&link).unwrap();
    let _ = std::fs::remove_dir_all(&target);
    let _ = std::fs::remove_dir_all(&container);
}
