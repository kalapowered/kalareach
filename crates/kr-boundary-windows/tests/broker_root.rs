//! The private root's creation and its removal under hostile contents, shown on a Windows guest.
//!
//! These cases run only in a disposable guest, as SYSTEM, under a Hyper-V checkpoint that is
//! restored afterwards. Each makes a root with the broker's own function, fills it with what a
//! taken-over Git could leave there, removes it with the broker's removal, and then looks at
//! everything outside the root, which must be as it was.

#![cfg(all(windows, feature = "testing"))]
#![allow(unsafe_code)]

mod common;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, HANDLE};
use windows_sys::Win32::Security::{ImpersonateLoggedOnUser, RevertToSelf};

use kr_boundary_windows::win::ffi::Handle;
use kr_boundary_windows::win::privilege;
use kr_boundary_windows::win::root::{
    Leftover, PrivateRoot, check_disposition, create_root, remove_root, remove_root_within,
};
use kr_boundary_windows::win::walk::Bounds;
use kr_boundary_windows::win::{account, broker, token};

use common::{Outside, Rows, Scratch, group, hostile_dir, hostile_file, look_at, run, run_dir};

const SYSTEM_SID: &str = "S-1-5-18";
const MODIFY: u32 = 0x0013_01bf;
const FULL: u32 = 0x001f_01ff;
const INHERIT_OBJECT_AND_CONTAINER: u8 = 0x03;

fn made_root(scratch: &Scratch) -> (common::Run, PrivateRoot, kr_boundary_windows::win::ffi::Sid) {
    let run = run_dir(scratch);
    let owner = group();
    let mut rows = Rows::default();
    let root = create_root(&run.dir, &run.path, &owner, &mut rows).expect("the root is made");
    (run, root, owner)
}

fn remove_with_the_walks_privileges(root: &PrivateRoot) -> (Vec<Leftover>, Vec<String>) {
    let guard = privilege::enter().expect("the walk's privileges can be enabled");
    let mut rows = Rows::default();
    let leftovers = remove_root(root, &guard, &mut rows).expect("the removal runs");
    drop(guard);
    (leftovers, rows.log)
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn the_root_is_made_by_one_call_with_the_descriptor_it_was_sent_and_its_rows_come_first() {
    let scratch = Scratch::new();
    let run = run_dir(&scratch);
    let owner = group();
    let mut rows = Rows::default();
    let root = create_root(&run.dir, &run.path, &owner, &mut rows).expect("the root is made");
    assert_eq!(
        rows.log.len(),
        2,
        "an intent and a made row: {:?}",
        rows.log
    );
    assert!(rows.log[0].starts_with("intent ") && rows.log[1].starts_with("made "));
    assert_eq!(
        rows.key,
        Some(root.key()),
        "the row carries the root's identity"
    );
    let name = root
        .path()
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    assert_eq!(name.len(), 32, "128 bits in hex: {name}");
    assert!(name.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')));
    let seen = look_at(root.path());
    assert_eq!(seen.summary.owner, SYSTEM_SID, "the system owns the root");
    assert!(
        seen.summary.protected,
        "the list takes nothing from the folder above"
    );
    let entries = seen.summary.entries.expect("the root has a list");
    assert_eq!(
        entries.len(),
        2,
        "the system and the group, nothing else: {entries:?}"
    );
    assert_eq!(
        (entries[0].sid.as_str(), entries[0].mask, entries[0].flags),
        (SYSTEM_SID, FULL, INHERIT_OBJECT_AND_CONTAINER)
    );
    assert_eq!(
        (entries[1].sid.clone(), entries[1].mask, entries[1].flags),
        (owner.to_text(), MODIFY, INHERIT_OBJECT_AND_CONTAINER)
    );
    for part in [root.tmp(), root.home()] {
        let inner = look_at(&part);
        assert_eq!(
            inner.summary.entries.as_ref().map(Vec::len),
            Some(2),
            "{} has the same two entries",
            part.display()
        );
        assert_eq!(inner.summary.owner, SYSTEM_SID);
    }
    let (leftovers, log) = remove_with_the_walks_privileges(&root);
    assert!(leftovers.is_empty(), "{leftovers:?}");
    assert_eq!(log, ["removed"], "the removed row is written once, last");
    assert!(!root.path().exists());
}

/// A throwaway account and two tokens of it with two invocation groups: the sibling case.
struct Siblings {
    account: String,
    first: Handle,
    second: Handle,
    first_group: kr_boundary_windows::win::ffi::Sid,
}

impl Siblings {
    fn new() -> Siblings {
        broker::init();
        for privilege in [
            "SeTcbPrivilege",
            "SeAssignPrimaryTokenPrivilege",
            "SeIncreaseQuotaPrivilege",
        ] {
            token::enable_privilege(privilege).unwrap();
        }
        let id = uuid::Uuid::new_v4().simple().to_string();
        let account = format!("krroot{}", &id[..6]);
        account::create(&account).expect("the throwaway account is made");
        let first_group = token::new_invocation_group();
        let second_group = token::new_invocation_group();
        Siblings {
            first: token::boundary_token(&account, &first_group).expect("the first token"),
            second: token::boundary_token(&account, &second_group).expect("the second token"),
            account,
            first_group,
        }
    }
}

impl Drop for Siblings {
    fn drop(&mut self) {
        let _ = account::delete(&self.account);
    }
}

/// Runs `body` as the token, on a thread of its own that ends the impersonation.
fn as_token<T: Send + 'static>(token: &Handle, body: impl FnOnce() -> T + Send + 'static) -> T {
    let raw = token.raw() as usize;
    std::thread::spawn(move || {
        // SAFETY: the token handle outlives the thread because the caller joins it.
        unsafe {
            assert_ne!(
                ImpersonateLoggedOnUser(raw as HANDLE),
                0,
                "the token can be impersonated"
            );
        }
        let out = body();
        // SAFETY: ends the impersonation this thread began.
        unsafe {
            RevertToSelf();
        }
        out
    })
    .join()
    .unwrap()
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn the_group_reaches_its_root_tmp_and_home_and_a_sibling_and_the_run_directory_do_not() {
    let siblings = Siblings::new();
    let scratch = Scratch::new();
    let run = run_dir(&scratch);
    let mut rows = Rows::default();
    let root = create_root(&run.dir, &run.path, &siblings.first_group, &mut rows).unwrap();
    for (name, part) in [
        ("root", root.path().to_owned()),
        ("tmp", root.tmp()),
        ("home", root.home()),
    ] {
        let target = part.join("made.txt");
        let wrote = as_token(&siblings.first, {
            let target = target.clone();
            move || std::fs::write(&target, b"1")
        });
        assert!(wrote.is_ok(), "the group writes in its {name}: {wrote:?}");
        let listed = as_token(&siblings.first, {
            let part = part.clone();
            move || std::fs::read_dir(&part).map(|entries| entries.count())
        });
        assert_eq!(listed.unwrap(), 1, "and lists it");
        let sibling = as_token(&siblings.second, {
            let part = part.clone();
            move || {
                (
                    std::fs::write(part.join("sibling.txt"), b"2").map_err(|e| e.raw_os_error()),
                    std::fs::read_dir(&part)
                        .map(|_| ())
                        .map_err(|e| e.raw_os_error()),
                    std::fs::remove_file(part.join("made.txt")).map_err(|e| e.raw_os_error()),
                )
            }
        });
        let denied = Err(Some(ERROR_ACCESS_DENIED as i32));
        assert_eq!(
            sibling,
            (denied, denied, denied),
            "a sibling can neither write, list nor delete in the {name}"
        );
    }
    let refused = as_token(&siblings.first, {
        let path = run.path.clone();
        move || {
            (
                std::fs::read_dir(&path)
                    .map(|_| ())
                    .map_err(|e| e.raw_os_error()),
                std::fs::create_dir(path.join("other")).map_err(|e| e.raw_os_error()),
            )
        }
    });
    let denied = Err(Some(ERROR_ACCESS_DENIED as i32));
    assert_eq!(
        refused,
        (denied, denied),
        "no boundary token may list, create in or delete from the run directory"
    );
    let (leftovers, _) = remove_with_the_walks_privileges(&root);
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_hard_link_name_is_removed_while_the_other_names_and_the_data_stay() {
    let scratch = Scratch::new();
    let (_run, root, _owner) = made_root(&scratch);
    let outside = scratch.path("outside.txt");
    std::fs::write(&outside, b"the data").unwrap();
    let second_outside_name = scratch.path("outside-too.txt");
    std::fs::hard_link(&outside, &second_outside_name).unwrap();
    std::fs::hard_link(&outside, root.tmp().join("link.txt")).unwrap();
    let before = look_at(&outside);
    assert_eq!(before.links, 3, "the file has three names");
    let (leftovers, _) = remove_with_the_walks_privileges(&root);
    assert!(leftovers.is_empty(), "{leftovers:?}");
    assert!(!root.path().exists(), "the root is gone");
    let after = look_at(&outside);
    assert_eq!(after.links, 2, "exactly one name went");
    assert_eq!(after.bytes, before.bytes, "the data stayed");
    assert_eq!(after.summary, before.summary, "the descriptor is as it was");
    assert_eq!(after.attributes, before.attributes);
    assert_eq!(std::fs::read(&second_outside_name).unwrap(), b"the data");
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_junction_and_a_symbolic_link_are_removed_as_themselves_and_their_targets_stay() {
    let scratch = Scratch::new();
    let (_run, root, _owner) = made_root(&scratch);
    let target_dir = scratch.path("target");
    std::fs::create_dir_all(target_dir.join("sub")).unwrap();
    std::fs::write(target_dir.join("file.txt"), b"keep me").unwrap();
    std::fs::write(target_dir.join("sub").join("deep.txt"), b"and me").unwrap();
    let target_file = scratch.path("target.txt");
    std::fs::write(&target_file, b"also me").unwrap();
    run(
        "cmd.exe",
        &[
            "/c",
            "mklink",
            "/J",
            &root.tmp().join("junction").display().to_string(),
            &target_dir.display().to_string(),
        ],
    );
    run(
        "cmd.exe",
        &[
            "/c",
            "mklink",
            "/D",
            &root.tmp().join("dirlink").display().to_string(),
            &target_dir.display().to_string(),
        ],
    );
    run(
        "cmd.exe",
        &[
            "/c",
            "mklink",
            &root.home().join("filelink").display().to_string(),
            &target_file.display().to_string(),
        ],
    );
    let before: Vec<Outside> = [
        target_dir.clone(),
        target_dir.join("file.txt"),
        target_dir.join("sub"),
        target_dir.join("sub").join("deep.txt"),
        target_file.clone(),
    ]
    .iter()
    .map(|path| look_at(path))
    .collect();
    let (leftovers, _) = remove_with_the_walks_privileges(&root);
    assert!(leftovers.is_empty(), "{leftovers:?}");
    assert!(!root.path().exists(), "the links and the root are gone");
    let after: Vec<Outside> = [
        target_dir.clone(),
        target_dir.join("file.txt"),
        target_dir.join("sub"),
        target_dir.join("sub").join("deep.txt"),
        target_file.clone(),
    ]
    .iter()
    .map(|path| look_at(path))
    .collect();
    assert_eq!(
        after, before,
        "every target's bytes, attributes and descriptor are as they were"
    );
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn objects_whose_list_refuses_the_system_and_read_only_files_are_removed_and_nothing_is_written() {
    let scratch = Scratch::new();
    let (_run, root, owner) = made_root(&scratch);
    common::privileged(|| {
        hostile_file(&root.tmp().join("file.txt"), &owner, b"bytes");
        hostile_file(&root.tmp().join("readonly.txt"), &owner, b"bytes");
        let path = root.tmp().join("readonly.txt");
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&path, permissions).unwrap();
        hostile_dir(&root.home().join("directory"), &owner);
        hostile_file(
            &root.home().join("directory").join("inside.txt"),
            &owner,
            b"bytes",
        );
    });
    let outside = scratch.path("bystander.txt");
    std::fs::write(&outside, b"unrelated").unwrap();
    let before = look_at(&outside);
    let (leftovers, log) = remove_with_the_walks_privileges(&root);
    assert!(leftovers.is_empty(), "{leftovers:?}");
    assert_eq!(log, ["removed"]);
    assert!(!root.path().exists());
    assert_eq!(
        look_at(&outside),
        before,
        "an object elsewhere was not touched"
    );
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn without_the_privileges_a_hostile_object_is_a_leftover_and_nothing_on_it_changes() {
    let scratch = Scratch::new();
    let (_run, root, owner) = made_root(&scratch);
    let stubborn = root.tmp().join("stubborn.txt");
    common::privileged(|| hostile_file(&stubborn, &owner, b"bytes"));
    let before = look_at(&stubborn);
    let guard = privilege::enter_with(&[]).expect("a guard with no privilege");
    let mut rows = Rows::default();
    let leftovers = remove_root(&root, &guard, &mut rows).expect("the removal runs");
    drop(guard);
    assert_eq!(leftovers.len(), 1, "{leftovers:?}");
    assert!(
        leftovers[0].path.ends_with("stubborn.txt"),
        "the leftover names the object: {:?}",
        leftovers[0]
    );
    assert!(
        rows.log.is_empty(),
        "no removed row is written while something is left"
    );
    assert_eq!(
        look_at(&stubborn),
        before,
        "nothing on the object changed: no list, no attribute, no owner"
    );
    let (rest, _) = remove_with_the_walks_privileges(&root);
    assert!(
        rest.is_empty(),
        "the next try, with the privileges, finishes: {rest:?}"
    );
}

fn extended(path: &Path) -> PathBuf {
    PathBuf::from(format!(r"\\?\{}", path.display()))
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn long_names_case_sensitive_names_and_streams_are_removed() {
    let scratch = Scratch::new();
    let (_run, root, _owner) = made_root(&scratch);
    let long = "a".repeat(200);
    let deep = root.tmp().join(&long).join(&long).join(&long);
    std::fs::create_dir_all(extended(&deep)).unwrap();
    std::fs::write(extended(&deep.join("file.txt")), b"deep").unwrap();
    assert!(
        deep.display().to_string().len() > 600,
        "past the old path limit"
    );
    let sensitive = root.home().join("sensitive");
    std::fs::create_dir(&sensitive).unwrap();
    run(
        "fsutil.exe",
        &[
            "file",
            "setCaseSensitiveInfo",
            &sensitive.display().to_string(),
            "enable",
        ],
    );
    std::fs::write(sensitive.join("Name"), b"upper").unwrap();
    std::fs::write(sensitive.join("name"), b"lower").unwrap();
    assert_eq!(
        std::fs::read_dir(&sensitive).unwrap().count(),
        2,
        "two names that differ only in case"
    );
    let with_stream = root.tmp().join("stream.txt");
    std::fs::write(&with_stream, b"base").unwrap();
    std::fs::write(format!("{}:hidden", with_stream.display()), b"in a stream").unwrap();
    let (leftovers, _) = remove_with_the_walks_privileges(&root);
    assert!(leftovers.is_empty(), "{leftovers:?}");
    assert!(
        !root.path().exists(),
        "everything is gone, the stream's file and both names included"
    );
}

fn open_without_sharing(path: &Path, share: u32) -> Handle {
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::IntoRawHandle as _;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(share)
        .open(path)
        .unwrap();
    Handle::new(file.into_raw_handle(), "an open file").unwrap()
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_file_in_use_with_delete_sharing_goes_at_once_and_one_without_it_is_a_leftover_until_closed() {
    let scratch = Scratch::new();
    let (_run, root, _owner) = made_root(&scratch);
    let shared = root.tmp().join("shared.txt");
    let held = root.tmp().join("held.txt");
    std::fs::write(&shared, b"1").unwrap();
    std::fs::write(&held, b"2").unwrap();
    let shared_open = open_without_sharing(&shared, 7);
    let held_open = open_without_sharing(&held, 3);
    let before = look_at(&held);
    let started = Instant::now();
    let (leftovers, log) = remove_with_the_walks_privileges(&root);
    assert!(
        started.elapsed() >= Duration::from_secs(5),
        "it waited for the file in use"
    );
    assert_eq!(leftovers.len(), 1, "{leftovers:?}");
    assert!(
        leftovers[0].path.ends_with("held.txt"),
        "{:?}",
        leftovers[0]
    );
    assert!(log.is_empty(), "no removed row while something is left");
    assert!(
        !shared.exists(),
        "the file opened with delete sharing is gone"
    );
    assert_eq!(look_at(&held), before, "the file in use is as it was");
    drop(shared_open);
    drop(held_open);
    let (rest, log) = remove_with_the_walks_privileges(&root);
    assert!(rest.is_empty(), "{rest:?}");
    assert_eq!(log, ["removed"]);
    assert!(!root.path().exists());
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_tree_past_the_bounds_is_a_leftover_not_a_walk_without_end() {
    let scratch = Scratch::new();
    let (_run, root, _owner) = made_root(&scratch);
    for index in 0..10 {
        std::fs::write(root.tmp().join(format!("f{index}.txt")), b"x").unwrap();
    }
    let guard = privilege::enter().unwrap();
    let mut rows = Rows::default();
    let leftovers = remove_root_within(
        &root,
        &guard,
        Bounds {
            objects: 5,
            depth: 8,
        },
        &mut rows,
    )
    .unwrap();
    assert!(
        leftovers.iter().any(|l| l.reason == "too large"),
        "{leftovers:?}"
    );
    assert!(
        root.path().exists(),
        "the root stays while something is left"
    );
    let mut rows = Rows::default();
    assert!(remove_root(&root, &guard, &mut rows).unwrap().is_empty());
    drop(guard);
    let deep = root.tmp().join("a").join("b").join("c");
    assert!(!deep.exists());
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn the_disposition_call_is_checked_on_a_scratch_file_and_leaves_nothing() {
    let scratch = Scratch::new();
    let run = run_dir(&scratch);
    check_disposition(&run.dir).expect("the platform's delete with POSIX semantics works here");
    assert_eq!(
        std::fs::read_dir(&run.path).unwrap().count(),
        0,
        "no scratch file stays"
    );
}
