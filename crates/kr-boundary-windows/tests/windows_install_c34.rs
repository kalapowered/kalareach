//! Guest cases for what the setup program's reads show of the local accounts where a refusal of the
//! data directory decides whether to name a move. They run only in a disposable Windows guest, as
//! SYSTEM, like the cases of `windows_install.rs`.

#![cfg(all(windows, feature = "testing"))]
#![allow(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

use kr_boundary_windows::win::install::{self, Paths};
use kr_boundary_windows::win::{account, acl, sd};

fn inherited_folder() -> PathBuf {
    let folder = std::env::temp_dir().join(format!(
        "krparent-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    std::fs::create_dir(&folder).unwrap();
    let done = Command::new("icacls")
        .arg(&folder)
        .args(["/setowner", "*S-1-5-32-544"])
        .output()
        .unwrap();
    assert!(done.status.success(), "{done:?}");
    folder
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

fn junction(link: &Path, target: &Path) {
    let made = Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .output()
        .unwrap();
    assert!(made.status.success(), "{made:?}");
}

/// Runs one line of PowerShell and checks that it ended well.
fn powershell(line: &str) {
    let done = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", line])
        .output()
        .unwrap();
    assert!(
        done.status.success(),
        "{line}: {}{}",
        String::from_utf8_lossy(&done.stdout),
        String::from_utf8_lossy(&done.stderr)
    );
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

/// What the case made: the account, which keeps no one name since the case renames it, and the
/// folders. The end removes them whether the case passes or fails.
struct Made {
    account: std::cell::RefCell<String>,
    link: PathBuf,
    folders: Vec<PathBuf>,
}

impl Drop for Made {
    fn drop(&mut self) {
        let _ = account::delete(&self.account.borrow());
        let _ = std::fs::remove_dir(&self.link);
        for folder in &self.folders {
            let _ = std::fs::remove_dir_all(folder);
        }
    }
}

/// An account that carries the installation's comment is found by that comment whatever its name is
/// now, and the setup program then names no move at an installation: the reads did not show that
/// nothing of an installation is left. An account that was renamed and whose comment was changed is
/// seen by no read, and the words say so beside the move.
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn an_account_that_keeps_the_installations_comment_withholds_the_move_after_a_rename_and_one_that_lost_it_is_not_seen()
 {
    if needs_the_system() {
        return;
    }
    let folder = inherited_folder();
    let target = inherited_folder();
    parent_of(&folder);
    let paths = paths_in(&folder);
    let id = &uuid::Uuid::new_v4().simple().to_string()[..6];
    let (made, renamed) = (format!("krowner{id}"), format!("krrenamed{id}"));
    let guard = Made {
        account: std::cell::RefCell::new(made.clone()),
        link: paths.data.clone(),
        folders: vec![folder.clone(), target.clone()],
    };
    junction(&paths.data, &target);
    let refused = || {
        install::make_data_directory(&paths)
            .expect_err("a link at the data directory")
            .to_string()
    };
    const MOVE: &str = "Move it aside only if you know that nothing of an installation is left";
    const NOT_SEEN: &str =
        "They do not see an account that was renamed and whose comment was changed.";
    const WITHHELD: &str = "did not show that nothing of an installation is left";

    // A clean computer: every read found nothing, so the move stands, with what the reads do not see.
    let text = refused();
    assert!(text.contains("it is a reparse point"), "{text}");
    assert!(text.contains(MOVE), "{text}");
    assert!(text.contains(NOT_SEEN), "{text}");
    assert!(!text.contains(WITHHELD), "{text}");

    // An account that carries the installation's comment, then renamed: the enumeration finds it by
    // the comment, names it, and no move is named.
    account::create(&made).unwrap();
    powershell(&format!(
        "Rename-LocalUser -Name '{made}' -NewName '{renamed}'"
    ));
    *guard.account.borrow_mut() = renamed.clone();
    let text = refused();
    assert!(
        text.contains(&format!(
            "an account carries the comment that the installation gives its accounts: {renamed}"
        )),
        "{text}"
    );
    assert!(text.contains(WITHHELD), "{text}");
    assert!(text.contains("It names no step for it."), "{text}");
    assert!(!text.contains(MOVE), "{text}");
    assert!(!text.contains("Move it aside"), "{text}");

    // The same account with its comment changed: no read sees it, the move stands, and the words say
    // what the reads do not see.
    powershell(&format!(
        "Set-LocalUser -Name '{renamed}' -Description 'an account of someone else'"
    ));
    let text = refused();
    assert!(text.contains(MOVE), "{text}");
    assert!(text.contains(NOT_SEEN), "{text}");
    assert!(!text.contains(&renamed), "{text}");
    assert!(!text.contains(WITHHELD), "{text}");

    // The account is gone: the reads find nothing again.
    account::delete(&renamed).unwrap();
    let text = refused();
    assert!(text.contains(MOVE), "{text}");
    drop(guard);
}
