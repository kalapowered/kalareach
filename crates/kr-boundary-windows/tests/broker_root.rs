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
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, GENERIC_READ, GENERIC_WRITE, HANDLE, WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::{ImpersonateLoggedOnUser, RevertToSelf};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ACTION_ADDED, FILE_ACTION_MODIFIED, FILE_ATTRIBUTE_NORMAL,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OVERLAPPED, FILE_LIST_DIRECTORY,
    FILE_NOTIFY_CHANGE_DIR_NAME, FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_SECURITY,
    FILE_NOTIFY_INFORMATION, GetShortPathNameW, OPEN_EXISTING, ReadDirectoryChangesW,
};
use windows_sys::Win32::System::IO::{DeviceIoControl, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject};

use kr_boundary_windows::filekey::FileKey;
use kr_boundary_windows::journal::rows::RootName;
use kr_boundary_windows::win::acl::{self, Reset};
use kr_boundary_windows::win::ffi::{Handle, Sid, wide_path};
use kr_boundary_windows::win::privilege;
use kr_boundary_windows::win::root::testing::{self as removal, Event};
use kr_boundary_windows::win::root::{
    Leftover, Limits, PrivateRoot, ROOT_LIMITS, RootError, RootRows, check_disposition,
    create_root, create_root_named, remove_root, remove_root_within,
};
use kr_boundary_windows::win::sd::{self, Principals, SdKind};
use kr_boundary_windows::win::walk::{
    AnchorRefusal, Bounds, DirHandle, RecordedDir, testing as walking,
};
use kr_boundary_windows::win::{account, broker, token};

use common::{Outside, Rows, Scratch, group, hostile_dir, hostile_file, look_at, run, run_dir};

const SYSTEM_SID: &str = "S-1-5-18";
const MODIFY: u32 = 0x0013_01bf;
const FULL: u32 = 0x001f_01ff;
const INHERIT_OBJECT_AND_CONTAINER: u8 = 0x03;

/// Rows that check, as each is written, what the `run` directory holds: nothing under the name
/// before the intent is durable, and the directory once it is recorded as made.
struct RunRows {
    run: PathBuf,
    rows: Rows,
}

impl RunRows {
    fn new(run: &common::Run) -> RunRows {
        RunRows {
            run: run.path.clone(),
            rows: Rows::default(),
        }
    }
}

impl std::ops::Deref for RunRows {
    type Target = Rows;

    fn deref(&self) -> &Rows {
        &self.rows
    }
}

impl RootRows for RunRows {
    fn intent(&mut self, name: &RootName) -> Result<(), RootError> {
        assert!(
            !self.run.join(name.as_str()).exists(),
            "the intent is durable before the directory exists"
        );
        self.rows.intent(name)
    }

    fn made(&mut self, name: &RootName, key: &FileKey) -> Result<(), RootError> {
        assert!(
            self.run.join(name.as_str()).exists(),
            "the root exists when it is recorded as made"
        );
        self.rows.made(name, key)
    }

    fn removed(&mut self) -> Result<(), RootError> {
        self.rows.removed()
    }
}

/// Notes the names a removal listed in `directory`, each as its path below the root.
fn note_listed(listed: &Mutex<Vec<String>>, directory: &str, names: &[String]) {
    let mut listed = listed.lock().unwrap();
    for name in names {
        listed.push(if directory.is_empty() {
            name.clone()
        } else {
            format!("{directory}\\{name}")
        });
    }
}

/// Asserts that the removal opened each name it listed once and no name twice, from the opens a
/// recording made on its root. A name opened a second time after its check is the removal reaching
/// for an object it did not check.
fn assert_each_listed_name_was_opened_once(opens: &[String], listed: &[String]) {
    assert!(!listed.is_empty(), "the removal listed something");
    for path in listed {
        let suffix = format!("\\{path}");
        let count = opens.iter().filter(|open| open.ends_with(&suffix)).count();
        assert_eq!(
            count, 1,
            "{path} was opened once by the removal, and not again after its check: {opens:?}"
        );
    }
}

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
    let mut rows = RunRows::new(&run);
    let root = create_root(&run.dir, &run.path, &owner, &mut rows).expect("the root is made");
    assert_eq!(
        rows.log.len(),
        2,
        "an intent and a made row: {:?}",
        rows.log
    );
    assert!(rows.log[0].starts_with("intent ") && rows.log[1].starts_with("made "));
    assert_eq!(
        rows.log[0].trim_start_matches("intent "),
        root.name().as_str(),
        "the row names the 32-digit name alone, never a path"
    );
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
    let entries = seen.summary.entries.clone().expect("the root has a list");
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
        assert_eq!(
            inner.summary,
            seen.summary,
            "{} has the root's whole descriptor",
            part.display()
        );
    }
    let (leftovers, log) = remove_with_the_walks_privileges(&root);
    assert!(leftovers.is_empty(), "{leftovers:?}");
    assert_eq!(log, ["removed"], "the removed row is written once, last");
    assert!(common::is_gone(root), "the root is gone");
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
        // The root also holds `tmp` and `home`; those two hold only the file made here.
        let expected = if name == "root" { 3 } else { 1 };
        assert_eq!(listed.unwrap(), expected, "and lists it");
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
    // A sibling can neither remove the root, move it nor make another name beside it.
    let sibling_against_run = as_token(&siblings.second, {
        let (path, root_path) = (run.path.clone(), root.path().to_owned());
        move || {
            (
                std::fs::remove_dir(&root_path).map_err(|e| e.raw_os_error()),
                std::fs::rename(&root_path, path.join("moved")).map_err(|e| e.raw_os_error()),
                std::fs::create_dir(path.join("other")).map_err(|e| e.raw_os_error()),
            )
        }
    });
    assert_eq!(
        sibling_against_run,
        (denied, denied, denied),
        "a sibling can neither remove, move nor replace another invocation's root"
    );
    assert!(
        root.path().exists()
            && !run.path.join("moved").exists()
            && !run.path.join("other").exists(),
        "and the run directory holds only the root"
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
    assert!(common::is_gone(root), "the root is gone");
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
    assert!(common::is_gone(root), "the links and the root are gone");
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
    assert!(common::is_gone(root), "the root is gone");
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
        common::is_gone(root),
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
    assert!(common::is_gone(root), "the root is gone");
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
        Limits {
            bounds: Bounds {
                objects: 5,
                depth: 8,
            },
            ..ROOT_LIMITS
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

/// Watches a directory and everything under it for the changes to what it holds, security changes
/// among them, from before a case acts until the case asks for what was seen.
struct Watch {
    directory: Handle,
    event: Handle,
    overlapped: Box<OVERLAPPED>,
    buffer: Vec<u64>,
    seen: Vec<(u32, String)>,
}

const WATCHED: u32 =
    FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_SECURITY;

impl Watch {
    fn start(path: &Path) -> Watch {
        let wide = wide_path(path);
        // SAFETY: the path is NUL-terminated and the call keeps nothing of it.
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_LIST_DIRECTORY,
                7,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                std::ptr::null_mut(),
            )
        };
        let directory = Handle::new(raw, "the watched directory").unwrap();
        // SAFETY: an unnamed manual-reset event with the default descriptor.
        let event = Handle::new(
            unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) },
            "an event",
        )
        .unwrap();
        let mut watch = Watch {
            directory,
            event,
            // SAFETY: an all-zero OVERLAPPED is the documented initial state.
            overlapped: Box::new(unsafe { std::mem::zeroed() }),
            buffer: vec![0_u64; 8192],
            seen: Vec::new(),
        };
        watch.issue();
        watch
    }

    fn issue(&mut self) {
        // SAFETY: as above.
        *self.overlapped = unsafe { std::mem::zeroed() };
        self.overlapped.hEvent = self.event.raw();
        // SAFETY: the buffer and the overlapped record live as long as the watch, which waits for
        // the call to finish before it reuses either.
        let issued = unsafe {
            ReadDirectoryChangesW(
                self.directory.raw(),
                self.buffer.as_mut_ptr().cast(),
                (self.buffer.len() * 8) as u32,
                1,
                WATCHED,
                std::ptr::null_mut(),
                &raw mut *self.overlapped,
                None,
            )
        };
        assert_ne!(issued, 0, "the directory can be watched");
    }

    /// Reads what happened until `name` was added. The case makes that its last change, so every
    /// change before it is in.
    fn until_added(&mut self, name: &str) {
        loop {
            // SAFETY: the event is open.
            let waited = unsafe { WaitForSingleObject(self.event.raw(), 20_000) };
            assert_eq!(waited, WAIT_OBJECT_0, "the watcher reports");
            let mut bytes = 0_u32;
            // SAFETY: the record is the one the call was issued with.
            let done = unsafe {
                GetOverlappedResult(
                    self.directory.raw(),
                    &raw const *self.overlapped,
                    &raw mut bytes,
                    0,
                )
            };
            assert!(done != 0 && bytes > 0, "the watcher's buffer holds changes");
            let base = self.buffer.as_ptr().cast::<u8>();
            let mut offset = 0_usize;
            loop {
                // SAFETY: the system filled records of this layout, each 4-byte aligned, and the
                // offset moves only by the length each record states.
                let record = unsafe { &*base.add(offset).cast::<FILE_NOTIFY_INFORMATION>() };
                let units = record.FileNameLength as usize / 2;
                // SAFETY: the name's units follow the fixed fields and lie inside the record.
                let text = unsafe {
                    std::slice::from_raw_parts(
                        std::ptr::addr_of!(record.FileName).cast::<u16>(),
                        units,
                    )
                };
                self.seen
                    .push((record.Action, String::from_utf16_lossy(text)));
                if record.NextEntryOffset == 0 {
                    break;
                }
                offset += record.NextEntryOffset as usize;
            }
            if self
                .seen
                .iter()
                .any(|(action, seen)| *action == FILE_ACTION_ADDED && seen == name)
            {
                return;
            }
            self.issue();
        }
    }
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn the_root_and_its_parts_have_their_descriptor_from_the_moment_they_exist_and_are_never_repaired()
{
    let scratch = Scratch::new();
    let run = run_dir(&scratch);
    let owner = group();
    let mut watch = Watch::start(&run.path);
    let mut rows = RunRows::new(&run);
    let root = create_root(&run.dir, &run.path, &owner, &mut rows).expect("the root is made");
    std::fs::create_dir(run.path.join("marker")).unwrap();
    watch.until_added("marker");
    let name = root.name().as_str().to_owned();
    let inside = format!("{name}\\");
    let mine: Vec<&(u32, String)> = watch
        .seen
        .iter()
        .filter(|(_, seen)| *seen == name || seen.starts_with(&inside))
        .collect();
    let mut added: Vec<&str> = mine
        .iter()
        .filter(|(action, _)| *action == FILE_ACTION_ADDED)
        .map(|(_, seen)| seen.as_str())
        .collect();
    added.sort_unstable();
    let mut expected = vec![
        name.clone(),
        format!("{name}\\home"),
        format!("{name}\\tmp"),
    ];
    expected.sort_unstable();
    assert_eq!(
        added, expected,
        "the watcher saw the three directories made"
    );
    assert!(
        mine.iter()
            .all(|(action, _)| *action != FILE_ACTION_MODIFIED),
        "no descriptor of the root or its parts changed after it was made: {mine:?}"
    );
    let (leftovers, _) = remove_with_the_walks_privileges(&root);
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_root_name_that_exists_refuses_the_invocation_and_changes_nothing_that_is_there() {
    let scratch = Scratch::new();
    let run = run_dir(&scratch);
    let name = RootName::parse("00112233445566778899aabbccddeeff").unwrap();
    let taken = run.path.join(name.as_str());
    std::fs::create_dir(&taken).unwrap();
    std::fs::write(taken.join("mine.txt"), b"not the broker's").unwrap();
    let before = (look_at(&taken), look_at(&taken.join("mine.txt")));
    let mut rows = Rows::default();
    match create_root_named(&run.dir, &run.path, name.clone(), &group(), &mut rows) {
        Err(RootError::Os(failure)) => assert_eq!(failure.code, 183, "the name exists"),
        other => panic!("a name that exists is refused: {other:?}"),
    }
    assert_eq!(
        rows.log,
        [format!("intent {}", name.as_str())],
        "the intent came first and no made row followed"
    );
    assert_eq!(
        (look_at(&taken), look_at(&taken.join("mine.txt"))),
        before,
        "what was there is as it was"
    );
}

fn extended_in(root: &PrivateRoot, name: &str) -> PathBuf {
    extended(&root.tmp().join(name))
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn names_that_end_in_a_dot_or_a_space_and_device_names_are_removed_exactly() {
    let scratch = Scratch::new();
    let (_run, root, _owner) = made_root(&scratch);
    let names = [
        "dot.", "space ", "both. ", "dot", "space", "con", "aux.txt", "nul", "com1.log", "end...",
    ];
    for name in names {
        std::fs::write(extended_in(&root, name), name.as_bytes()).unwrap();
    }
    std::fs::create_dir(extended_in(&root, "dir. ")).unwrap();
    std::fs::write(extended_in(&root, "dir. ").join("inner. "), b"i").unwrap();
    assert_eq!(
        std::fs::read_dir(extended(&root.tmp())).unwrap().count(),
        names.len() + 1,
        "every name exists apart from the one it would be read as by a path"
    );
    let bystander = scratch.path("dot");
    std::fs::write(&bystander, b"unrelated").unwrap();
    let before = look_at(&bystander);
    let (leftovers, _) = remove_with_the_walks_privileges(&root);
    assert!(leftovers.is_empty(), "{leftovers:?}");
    assert!(common::is_gone(root), "every name is gone, root included");
    assert_eq!(
        look_at(&bystander),
        before,
        "an object elsewhere was not touched"
    );
}

fn short_form(path: &Path) -> String {
    let wide = wide_path(path);
    let mut buffer = [0_u16; 520];
    // SAFETY: the path is NUL-terminated and the buffer length is passed.
    let length =
        unsafe { GetShortPathNameW(wide.as_ptr(), buffer.as_mut_ptr(), buffer.len() as u32) };
    String::from_utf16_lossy(&buffer[..length as usize])
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn objects_with_short_names_and_names_that_look_like_short_names_are_removed_by_their_long_names() {
    let scratch = Scratch::new();
    let (_run, root, _owner) = made_root(&scratch);
    let long = root.tmp().join("a long file name for a short name.txt");
    let directory = root.tmp().join("a long directory name for a short name");
    std::fs::write(&long, b"file").unwrap();
    std::fs::create_dir(&directory).unwrap();
    std::fs::write(
        directory.join("an inner file with a long name.txt"),
        b"inner",
    )
    .unwrap();
    let short = short_form(&long);
    let alias = Path::new(&short)
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    assert!(
        alias.contains('~') && alias != long.file_name().unwrap().to_string_lossy(),
        "the volume gives the file itself a short name, or the case shows nothing: {short}"
    );
    // Long names that are another object's short alias can only be made when no object has the
    // alias yet; these are made by their long form and sit beside objects that have aliases.
    for name in ["ALONGF~7.TXT", "ALONGD~7", "ALONGF~9.TXT"] {
        let path = root.tmp().join(name);
        if name.ends_with(".TXT") {
            std::fs::write(&path, name.as_bytes()).unwrap();
        } else {
            std::fs::create_dir(&path).unwrap();
        }
    }
    let bystander = scratch.path("ALONGF~1.TXT");
    std::fs::write(&bystander, b"unrelated").unwrap();
    let before = look_at(&bystander);
    let (leftovers, _) = remove_with_the_walks_privileges(&root);
    assert!(leftovers.is_empty(), "{leftovers:?}");
    assert!(common::is_gone(root), "every object is gone, root included");
    assert_eq!(
        look_at(&bystander),
        before,
        "an object elsewhere was not touched"
    );
}

/// Opens the named stream of a file and holds it, then removes the root with short waits. Gives
/// what was left over and whether the file stayed.
fn remove_while_a_stream_is_held(share: u32) -> (Vec<Leftover>, bool) {
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::IntoRawHandle as _;
    let scratch = Scratch::new();
    let (_run, root, _owner) = made_root(&scratch);
    let file = root.tmp().join("with-stream.txt");
    std::fs::write(&file, b"base").unwrap();
    std::fs::write(format!("{}:hidden", file.display()), b"in a stream").unwrap();
    let stream = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(share)
        .open(format!("{}:hidden", file.display()))
        .unwrap();
    let held = Handle::new(stream.into_raw_handle(), "an open stream").unwrap();
    let guard = privilege::enter().unwrap();
    let mut rows = Rows::default();
    let leftovers = remove_root_within(
        &root,
        &guard,
        Limits {
            wait_each: Duration::from_secs(1),
            wait_total: Duration::from_secs(2),
            ..ROOT_LIMITS
        },
        &mut rows,
    )
    .unwrap();
    drop(guard);
    let stays = file.exists();
    println!(
        "stream opened with sharing {share}: leftovers {leftovers:?}, the file stays: {stays}"
    );
    drop(held);
    let (rest, _) = remove_with_the_walks_privileges(&root);
    assert!(
        rest.is_empty(),
        "after the stream closes the next removal finishes: {rest:?}"
    );
    assert!(common::is_gone(root), "the root is gone");
    (leftovers, stays)
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_file_whose_stream_another_process_holds_open_is_removed_or_left_over_and_never_lost() {
    let (leftovers, stays) = remove_while_a_stream_is_held(7);
    assert!(
        leftovers.is_empty() && !stays,
        "delete sharing lets the file go, stream and all: {leftovers:?} {stays}"
    );
    let (leftovers, stays) = remove_while_a_stream_is_held(3);
    assert!(
        stays,
        "a stream held without delete sharing keeps the file in use"
    );
    assert_eq!(
        leftovers,
        [Leftover {
            path: "tmp\\with-stream.txt".to_owned(),
            reason: "in use".to_owned()
        }],
        "and the removal says so and leaves nothing else"
    );
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_link_replaced_by_another_object_after_the_listing_is_a_leftover_and_nothing_is_deleted() {
    let scratch = Scratch::new();
    let (_run, root, _owner) = made_root(&scratch);
    let outside = scratch.path("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("victim.txt"), b"keep").unwrap();
    let link = root.tmp().join("swap-link");
    run(
        "cmd.exe",
        &[
            "/c",
            "mklink",
            "/J",
            &link.display().to_string(),
            &outside.display().to_string(),
        ],
    );
    let moved = scratch.path("moved.txt");
    let before = (look_at(&outside), look_at(&outside.join("victim.txt")));
    let opened = Arc::new(Mutex::new(Vec::<String>::new()));
    let listed = Arc::new(Mutex::new(Vec::<String>::new()));
    {
        let (opened, listed, link, moved) =
            (opened.clone(), listed.clone(), link.clone(), moved.clone());
        removal::set(root.name(), move |event| match event {
            Event::Listed {
                directory, names, ..
            } => {
                note_listed(&listed, directory, names);
                if *directory == "tmp" {
                    // After the listing and before the open: a sibling takes the junction away and
                    // puts a plain file under its name.
                    std::fs::remove_dir(&link).unwrap();
                    std::fs::write(&link, b"swapped in").unwrap();
                }
            }
            Event::Opened { path } if *path == "tmp\\swap-link" => {
                opened.lock().unwrap().push((*path).to_owned());
                // Were the object open for a rename, this would send it outside the root.
                let _ = std::fs::rename(&link, &moved);
            }
            _ => {}
        });
    }
    let recording = walking::record(root.name().as_str());
    let (leftovers, log) = remove_with_the_walks_privileges(&root);
    removal::clear(root.name());
    let opens = recording.opens();
    assert_each_listed_name_was_opened_once(&opens, &listed.lock().unwrap());
    assert!(
        opened.lock().unwrap().is_empty(),
        "the name that holds another object is not opened for removal"
    );
    assert_eq!(leftovers.len(), 1, "{leftovers:?}");
    assert_eq!(leftovers[0].path, "tmp\\swap-link", "{leftovers:?}");
    assert!(log.is_empty(), "no removed row while something is left");
    assert_eq!(
        std::fs::read(&link).unwrap(),
        b"swapped in",
        "what was swapped in is a leftover and is as it was"
    );
    assert!(!moved.exists(), "nothing left the root");
    assert_eq!(
        (look_at(&outside), look_at(&outside.join("victim.txt"))),
        before,
        "nothing outside the root was reached"
    );
    let (rest, _) = remove_with_the_walks_privileges(&root);
    assert!(rest.is_empty(), "the next removal takes it: {rest:?}");
    assert!(common::is_gone(root), "the root is gone");
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_link_or_a_file_with_several_names_stays_held_between_its_check_and_its_deletion() {
    let scratch = Scratch::new();
    let (_run, root, _owner) = made_root(&scratch);
    let outside = scratch.path("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("victim.txt"), b"keep").unwrap();
    let file_target = scratch.path("target.txt");
    std::fs::write(&file_target, b"target").unwrap();
    let kept_name = scratch.path("other-name.txt");
    std::fs::write(root.tmp().join("held-two-names.txt"), b"two names").unwrap();
    std::fs::hard_link(root.tmp().join("held-two-names.txt"), &kept_name).unwrap();
    for (flag, name, target) in [
        ("/J", "held-junction", &outside),
        ("/D", "held-dirlink", &outside),
        ("", "held-filelink", &file_target),
    ] {
        let path = root.tmp().join(name).display().to_string();
        let target = target.display().to_string();
        let mut arguments = vec!["/c", "mklink"];
        if !flag.is_empty() {
            arguments.push(flag);
        }
        arguments.extend([path.as_str(), target.as_str()]);
        run("cmd.exe", &arguments);
    }
    let before = (
        look_at(&outside),
        look_at(&outside.join("victim.txt")),
        look_at(&file_target),
        look_at(&kept_name),
    );
    let attempts = Arc::new(Mutex::new(Vec::<(String, Option<i32>)>::new()));
    let listed = Arc::new(Mutex::new(Vec::<String>::new()));
    {
        let (attempts, listed, tmp, away) = (
            attempts.clone(),
            listed.clone(),
            root.tmp(),
            scratch.path("away"),
        );
        removal::set(root.name(), move |event| {
            if let Event::Listed {
                directory, names, ..
            } = event
            {
                note_listed(&listed, directory, names);
            }
            if let Event::Opened { path } = event
                && let Some(name) = path.strip_prefix("tmp\\held-")
            {
                let from = tmp.join(format!("held-{name}"));
                let result = std::fs::rename(&from, away.with_file_name(format!("away-{name}")));
                attempts.lock().unwrap().push((
                    name.to_owned(),
                    result.err().and_then(|error| error.raw_os_error()),
                ));
            }
        });
    }
    let recording = walking::record(root.name().as_str());
    let (leftovers, log) = remove_with_the_walks_privileges(&root);
    removal::clear(root.name());
    assert_each_listed_name_was_opened_once(&recording.opens(), &listed.lock().unwrap());
    let attempts = attempts.lock().unwrap();
    assert_eq!(
        attempts.len(),
        4,
        "each of the four was opened and checked: {attempts:?}"
    );
    for (name, code) in attempts.iter() {
        assert_eq!(
            *code,
            Some(32),
            "{name}: a rename between the check and the deletion meets a sharing violation"
        );
    }
    assert!(leftovers.is_empty(), "{leftovers:?}");
    assert_eq!(log, ["removed"]);
    assert!(common::is_gone(root), "the root is gone");
    let (outside_before, victim_before, target_before, kept_before) = before;
    assert_eq!(
        (
            look_at(&outside),
            look_at(&outside.join("victim.txt")),
            look_at(&file_target),
        ),
        (outside_before, victim_before, target_before),
        "the targets are as they were"
    );
    let kept_after = look_at(&kept_name);
    assert_eq!(
        (kept_before.links, kept_after.links),
        (2, 1),
        "the other name of the hard link is now the object's only name"
    );
    assert_eq!(
        (kept_after.bytes, kept_after.summary, kept_after.attributes),
        (
            kept_before.bytes,
            kept_before.summary,
            kept_before.attributes
        ),
        "and its data, its descriptor and its attributes are as they were"
    );
    for name in [
        "away-junction",
        "away-dirlink",
        "away-filelink",
        "away-two-names.txt",
    ] {
        assert!(
            !scratch.path(name).exists(),
            "{name}: nothing left the root"
        );
    }
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn an_object_that_cannot_be_read_after_it_opens_is_a_leftover_and_the_removal_goes_on() {
    let scratch = Scratch::new();
    let (_run, root, _owner) = made_root(&scratch);
    for name in ["unread-a.txt", "unread-b.txt", "unread-c.txt"] {
        std::fs::write(root.tmp().join(name), b"x").unwrap();
    }
    std::fs::create_dir(root.home().join("unread-dir")).unwrap();
    std::fs::write(root.home().join("unread-dir").join("inside.txt"), b"x").unwrap();
    walking::fail_next_read_of("unread-b.txt");
    walking::fail_next_read_of("unread-dir");
    let (leftovers, log) = remove_with_the_walks_privileges(&root);
    let mut paths: Vec<&str> = leftovers.iter().map(|l| l.path.as_str()).collect();
    paths.sort_unstable();
    assert_eq!(
        paths,
        ["home\\unread-dir", "tmp\\unread-b.txt"],
        "{leftovers:?}"
    );
    assert!(
        leftovers
            .iter()
            .all(|l| l.reason.contains("read after it was opened")),
        "{leftovers:?}"
    );
    assert!(log.is_empty(), "no removed row while something is left");
    assert!(
        !root.tmp().join("unread-a.txt").exists() && !root.tmp().join("unread-c.txt").exists(),
        "the removal went on past the object it could not read"
    );
    let (rest, _) = remove_with_the_walks_privileges(&root);
    assert!(rest.is_empty(), "the next removal finishes: {rest:?}");
    assert!(common::is_gone(root), "the root is gone");
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn the_listing_stops_at_the_object_budget_and_a_root_that_is_too_large_is_one_leftover() {
    let scratch = Scratch::new();
    let (_run, root, _owner) = made_root(&scratch);
    // More than one read of the platform's buffer holds, so that a read of the whole directory
    // that is cut afterwards takes more calls than a read that stops at the budget.
    for index in 0..1000 {
        std::fs::write(root.tmp().join(format!("f{index}.txt")), b"x").unwrap();
    }
    for index in 0..50 {
        std::fs::write(root.home().join(format!("g{index}.txt")), b"x").unwrap();
    }
    let listed = Arc::new(Mutex::new(Vec::<(String, usize, bool)>::new()));
    {
        let listed = listed.clone();
        removal::set(root.name(), move |event| {
            if let Event::Listed {
                directory,
                names,
                more,
            } = event
            {
                listed
                    .lock()
                    .unwrap()
                    .push(((*directory).to_owned(), names.len(), *more));
            }
        });
    }
    let recording = walking::record(root.name().as_str());
    let guard = privilege::enter().unwrap();
    let mut rows = Rows::default();
    let leftovers = remove_root_within(
        &root,
        &guard,
        Limits {
            bounds: Bounds {
                objects: 8,
                depth: 8,
            },
            ..ROOT_LIMITS
        },
        &mut rows,
    )
    .unwrap();
    removal::clear(root.name());
    let calls_bounded = recording.listing_calls("\\tmp");
    let listed = listed.lock().unwrap().clone();
    let total: usize = listed.iter().map(|(_, count, _)| *count).sum();
    assert!(total <= 8, "no listing went past the budget: {listed:?}");
    assert!(
        listed.iter().any(|(_, _, more)| *more),
        "a listing said that it stopped early: {listed:?}"
    );
    assert!(
        calls_bounded <= 2,
        "the thousand names of tmp were listed by one read that stopped at the budget and one that looked for a child after it, not read whole: {calls_bounded}"
    );
    assert_eq!(
        leftovers
            .iter()
            .filter(|l| l.reason == "too large")
            .map(|l| l.path.as_str())
            .collect::<Vec<_>>(),
        [""],
        "one leftover, for the root and not for one child or directory: {leftovers:?}"
    );
    assert!(
        leftovers.len() <= 3,
        "and nothing more than that and the directories that stay for it: {leftovers:?}"
    );
    assert!(
        rows.log.is_empty(),
        "no removed row while something is left"
    );
    drop(guard);
    let (rest, _) = remove_with_the_walks_privileges(&root);
    assert!(
        rest.is_empty(),
        "within the usual limits the next removal finishes: {rest:?}"
    );
    assert!(
        recording.listing_calls("\\tmp") - calls_bounded >= 3,
        "tmp takes several reads to list whole, or the count above shows nothing"
    );
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_tree_nested_past_the_depth_bound_is_one_leftover_and_not_one_for_each_directory() {
    let scratch = Scratch::new();
    let (_run, root, _owner) = made_root(&scratch);
    for chain in ["a", "b", "c"] {
        let deep = root
            .tmp()
            .join(chain)
            .join("1")
            .join("2")
            .join("3")
            .join("4");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join("file.txt"), b"x").unwrap();
    }
    let guard = privilege::enter().unwrap();
    let mut rows = Rows::default();
    let leftovers = remove_root_within(
        &root,
        &guard,
        Limits {
            bounds: Bounds {
                objects: 1000,
                depth: 3,
            },
            ..ROOT_LIMITS
        },
        &mut rows,
    )
    .unwrap();
    drop(guard);
    assert_eq!(leftovers.len(), 1, "{leftovers:?}");
    assert_eq!(leftovers[0].reason, "too large");
    assert_eq!(leftovers[0].path, "", "it is the root's leftover");
    let (rest, _) = remove_with_the_walks_privileges(&root);
    assert!(
        rest.is_empty(),
        "within the usual limits the next removal finishes: {rest:?}"
    );
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn the_waits_for_objects_in_use_add_up_to_a_bound_for_the_whole_root() {
    let scratch = Scratch::new();
    let (_run, root, _owner) = made_root(&scratch);
    let mut held = Vec::new();
    for index in 0..6 {
        let path = root.tmp().join(format!("busy{index}.txt"));
        std::fs::write(&path, b"x").unwrap();
        held.push(open_without_sharing(&path, 3));
    }
    let guard = privilege::enter().unwrap();
    let mut rows = Rows::default();
    let started = Instant::now();
    let leftovers = remove_root_within(
        &root,
        &guard,
        Limits {
            wait_each: Duration::from_secs(2),
            wait_total: Duration::from_secs(3),
            ..ROOT_LIMITS
        },
        &mut rows,
    )
    .unwrap();
    let spent = started.elapsed();
    drop(guard);
    assert_eq!(leftovers.len(), 6, "{leftovers:?}");
    assert!(
        leftovers.iter().all(|l| l.reason == "in use"),
        "{leftovers:?}"
    );
    assert!(
        spent >= Duration::from_secs(3),
        "it waited for the first objects: {spent:?}"
    );
    assert!(
        spent < Duration::from_secs(9),
        "six objects at two seconds each would take twelve; the total bound ended the waiting: {spent:?}"
    );
    drop(held);
    let (rest, _) = remove_with_the_walks_privileges(&root);
    assert!(rest.is_empty(), "{rest:?}");
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_repair_sets_the_run_directorys_list_on_its_handle_and_only_when_it_is_empty() {
    let scratch = Scratch::new();
    let wanted = sd::descriptor(SdKind::AdminDir, &Principals::default()).unwrap();
    let directory = scratch.path("repaired");
    std::fs::create_dir(&directory).unwrap();
    assert_eq!(
        acl::set_protected_when_empty(&directory, &wanted).unwrap(),
        Reset::Applied
    );
    let entries = look_at(&directory)
        .summary
        .entries
        .expect("the directory has a list");
    assert_eq!(
        entries
            .iter()
            .map(|entry| (entry.kind, entry.flags, entry.mask, entry.sid.as_str()))
            .collect::<Vec<_>>(),
        [
            (0, INHERIT_OBJECT_AND_CONTAINER, FULL, SYSTEM_SID),
            (0, INHERIT_OBJECT_AND_CONTAINER, FULL, "S-1-5-32-544"),
        ],
        "an empty directory takes the system's and the administrators' list"
    );
    assert!(
        look_at(&directory).summary.protected,
        "and stops inheriting"
    );
    // A directory that holds something is not changed.
    let held = scratch.path("holds-something");
    std::fs::create_dir(&held).unwrap();
    std::fs::write(held.join("child.txt"), b"x").unwrap();
    let before = (look_at(&held), look_at(&held.join("child.txt")));
    assert_eq!(
        acl::set_protected_when_empty(&held, &wanted).unwrap(),
        Reset::NotEmpty
    );
    assert_eq!(
        (look_at(&held), look_at(&held.join("child.txt"))),
        before,
        "neither the directory nor its child changed"
    );
    // A junction is not followed and its target is not changed.
    let outside = scratch.path("outside");
    std::fs::create_dir(&outside).unwrap();
    let link = scratch.path("link");
    run(
        "cmd.exe",
        &[
            "/c",
            "mklink",
            "/J",
            &link.display().to_string(),
            &outside.display().to_string(),
        ],
    );
    let target_before = look_at(&outside);
    assert_eq!(
        acl::set_protected_when_empty(&link, &wanted).unwrap(),
        Reset::Refused(AnchorRefusal::ReparsePoint)
    );
    assert_eq!(look_at(&outside), target_before, "the target is as it was");
}

/// An opportunistic lock that a process holds on a file and never gives up: a break that the
/// platform asks of it is never answered.
struct Lock {
    _file: Handle,
    event: Handle,
    _overlapped: Box<OVERLAPPED>,
    _input: Box<[u32; 3]>,
    _output: Box<[u32; 6]>,
}

const FSCTL_REQUEST_OPLOCK: u32 = 0x0009_0240;
const LOCK_READ: u32 = 1;
const LOCK_HANDLE: u32 = 2;
const LOCK_WRITE: u32 = 4;

impl Lock {
    /// Takes a lock of the given levels (read, handle and write caching, alone or together).
    fn take(path: &Path, levels: u32) -> Lock {
        Lock::take_sharing(path, levels, 7)
    }

    /// As [`Lock::take`], with the sharing the holder's own open allows (read 1, write 2 and
    /// delete 4).
    fn take_sharing(path: &Path, levels: u32, share: u32) -> Lock {
        let wide = wide_path(path);
        // SAFETY: the path is NUL-terminated and the call keeps nothing of it.
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                share,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED | FILE_FLAG_BACKUP_SEMANTICS,
                std::ptr::null_mut(),
            )
        };
        let file = Handle::new(raw, "the file the lock is taken on").unwrap();
        // SAFETY: an unnamed manual-reset event with the default descriptor.
        let event = Handle::new(
            unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) },
            "an event",
        )
        .unwrap();
        // REQUEST_OPLOCK_INPUT_BUFFER: version 1, its length 12, the levels and the flag that
        // requests.
        let mut input = Box::new([1_u32 | (12 << 16), levels, 1]);
        let mut output = Box::new([0_u32; 6]);
        // SAFETY: an all-zero OVERLAPPED is the documented initial state.
        let mut overlapped: Box<OVERLAPPED> = Box::new(unsafe { std::mem::zeroed() });
        overlapped.hEvent = event.raw();
        // SAFETY: the buffers and the overlapped record are boxed and live as long as the lock,
        // which closes the file before they are freed.
        let asked = unsafe {
            DeviceIoControl(
                file.raw(),
                FSCTL_REQUEST_OPLOCK,
                input.as_mut_ptr().cast(),
                12,
                output.as_mut_ptr().cast(),
                24,
                std::ptr::null_mut(),
                &raw mut *overlapped,
            )
        };
        let error = std::io::Error::last_os_error().raw_os_error();
        assert!(
            asked == 0 && error == Some(997),
            "the lock is granted and waits for a break (a granted request is pending): {asked} {error:?}"
        );
        Lock {
            _file: file,
            event,
            _overlapped: overlapped,
            _input: input,
            _output: output,
        }
    }

    /// Whether a break of the lock was asked for.
    fn break_was_asked_for(&self) -> bool {
        // SAFETY: the event is open.
        unsafe { WaitForSingleObject(self.event.raw(), 0) == WAIT_OBJECT_0 }
    }
}

/// The waits the lock and delete cases give a removal.
const LIMITS: Limits = Limits {
    wait_each: Duration::from_secs(1),
    wait_total: Duration::from_secs(2),
    ..ROOT_LIMITS
};
/// The longest a removal within [`LIMITS`] may take: the total, the half second a delete call is
/// given once the total is spent, the two seconds it is waited for after a cancel, and a second.
const AT_MOST: Duration = Duration::from_millis(2000 + 500 + 2000 + 1000);

/// Runs `body` on a thread and fails the case when it has not returned within `deadline`.
fn on_a_thread<T: Send + 'static>(
    deadline: Duration,
    body: impl FnOnce() -> T + Send + 'static,
) -> T {
    let (send, receive) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = send.send(body());
    });
    receive
        .recv_timeout(deadline)
        .unwrap_or_else(|_| panic!("the call did not return within {deadline:?}"))
}

/// How long the removal waits for a delete call after it has asked the system to cancel it.
const GRACE: Duration = Duration::from_secs(2);

/// What a removal that ran on a thread of its own gave back.
struct Removed {
    root: PrivateRoot,
    leftovers: Vec<Leftover>,
    log: Vec<String>,
    spent: Duration,
}

/// Runs the removal on a thread with the walk's privileges and fails the case when it has not
/// returned within `deadline`, so that a call that waits for ever is a failed assertion and not a
/// program that never ends.
fn remove_on_a_thread(root: PrivateRoot, limits: Limits, deadline: Duration) -> Removed {
    let (send, receive) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let guard = privilege::enter().unwrap();
        let mut rows = Rows::default();
        let started = Instant::now();
        let leftovers = remove_root_within(&root, &guard, limits, &mut rows).unwrap();
        let spent = started.elapsed();
        drop(guard);
        let _ = send.send(Removed {
            root,
            leftovers,
            log: rows.log,
            spent,
        });
    });
    receive
        .recv_timeout(deadline)
        .unwrap_or_else(|_| panic!("the removal did not return within {deadline:?}"))
}

/// Waits until `condition` holds, and fails the case when it does not within ten seconds.
fn wait_until(what: &str, condition: impl Fn() -> bool) {
    let until = Instant::now() + Duration::from_secs(10);
    while !condition() {
        assert!(Instant::now() < until, "{what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn names_in(directory: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_file_held_by_a_lock_that_is_not_given_up_is_removed_or_in_use_within_the_waits_for_every_kind()
{
    for (levels, kind) in [
        (LOCK_READ, "read"),
        (LOCK_READ | LOCK_HANDLE, "read and handle"),
        (LOCK_READ | LOCK_WRITE, "read and write"),
        (
            LOCK_READ | LOCK_WRITE | LOCK_HANDLE,
            "read, write and handle",
        ),
    ] {
        let scratch = Scratch::new();
        let (_run, root, _owner) = made_root(&scratch);
        let held = root.tmp().join("locked.txt");
        std::fs::write(&held, b"locked").unwrap();
        let lock = Lock::take(&held, levels);
        let name = root.name().clone();
        let done = remove_on_a_thread(root, LIMITS, Duration::from_secs(30));
        let asked = lock.break_was_asked_for();
        let cancels = removal::cancels(&name);
        println!(
            "lock of {kind}: break asked for {asked}, cancels {cancels}, {:?}, {:?}",
            done.leftovers, done.spent
        );
        assert!(
            done.spent <= AT_MOST,
            "{kind}: no call of the removal waited for the lock's break: {:?}",
            done.spent
        );
        assert!(
            cancels <= 1,
            "{kind}: one delete call at most was cancelled"
        );
        match done.leftovers.as_slice() {
            [] => assert!(!held.exists(), "{kind}: removed means gone"),
            [one] => {
                assert_eq!(
                    (one.path.as_str(), one.reason.as_str()),
                    ("tmp\\locked.txt", "in use"),
                    "{kind}: a lock that is not given up makes the object one in use"
                );
                assert!(
                    asked,
                    "{kind}: the lock was asked to give up, or nothing held the object"
                );
                assert!(
                    done.spent >= LIMITS.wait_each,
                    "{kind}: the removal waited for the object as long as it may: {:?}",
                    done.spent
                );
                assert!(held.exists(), "{kind}: the object is as it was");
            }
            more => panic!("{kind}: {more:?}"),
        }
        if levels == LOCK_READ | LOCK_WRITE | LOCK_HANDLE {
            // Shown in a guest: the open of an object with a lock of every level owes it a break,
            // so the open is refused and no delete call is made.
            assert_eq!(cancels, 0, "{kind}: the open refused the object");
            assert_eq!(done.leftovers.len(), 1, "{kind}: and it is a leftover");
        }
        drop(lock);
        let (rest, _) = remove_with_the_walks_privileges(&done.root);
        assert!(rest.is_empty(), "{kind}: once the lock is gone: {rest:?}");
        assert!(common::is_gone(done.root), "{kind}: the root is gone");
    }
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn the_roots_own_delete_under_a_lock_on_the_root_directory_is_removed_or_in_use_within_the_waits() {
    let scratch = Scratch::new();
    let (_run, root, _owner) = made_root(&scratch);
    let lock = Lock::take(root.path(), LOCK_READ | LOCK_HANDLE);
    let path = root.path().to_owned();
    let name = root.name().clone();
    let done = remove_on_a_thread(root, LIMITS, Duration::from_secs(30));
    let asked = lock.break_was_asked_for();
    let cancels = removal::cancels(&name);
    println!(
        "lock on the root directory: break asked for {asked}, cancels {cancels}, {:?}, {:?}",
        done.leftovers, done.spent
    );
    assert!(done.spent <= AT_MOST, "{:?}", done.spent);
    let removed = done.leftovers.is_empty();
    match done.leftovers.as_slice() {
        [] => assert_eq!(done.log, ["removed"]),
        [one] => {
            assert_eq!(
                (one.path.as_str(), one.reason.as_str()),
                ("", "in use"),
                "the leftover is the root's"
            );
            assert!(asked, "the lock was asked to give up");
            assert_eq!(cancels, 1, "the one delete call that waited was cancelled");
            assert!(done.spent >= LIMITS.wait_each, "{:?}", done.spent);
            assert!(path.exists() && done.log.is_empty());
        }
        more => panic!("{more:?}"),
    }
    drop(lock);
    if !removed {
        let (rest, _) = remove_with_the_walks_privileges(&done.root);
        assert!(rest.is_empty(), "once the lock is gone: {rest:?}");
    }
    // The name goes when the root's own handle closes: the delete was made through a copy of it,
    // and the two share one file object.
    assert!(common::is_gone(done.root), "the root is gone");
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn the_roots_own_delete_goes_through_the_same_thread_and_a_call_that_does_not_end_is_given_up() {
    let scratch = Scratch::new();
    let (_run, root, _owner) = made_root(&scratch);
    let name = root.name().clone();
    let path = root.path().to_owned();
    // The root is made empty first, so that its own delete is the removal's first call.
    std::fs::remove_dir(root.tmp()).unwrap();
    std::fs::remove_dir(root.home()).unwrap();
    // The held thread has no request pending in the system, which no cancel reaches: it stands for
    // a delete call that cannot be cancelled.
    let hold = removal::hold_deletes(&name);
    let done = remove_on_a_thread(root, LIMITS, Duration::from_secs(30));
    assert_eq!(
        done.leftovers,
        [Leftover {
            path: String::new(),
            reason: "the delete call did not end".to_owned()
        }],
        "one leftover, the root's: the root's delete was made on the thread that is held"
    );
    assert_eq!(
        removal::cancels(&name),
        1,
        "the system was asked to cancel the call once"
    );
    assert!(
        done.spent >= LIMITS.wait_each + GRACE && done.spent <= AT_MOST,
        "the removal waited for the limit and the whole grace and then returned: {:?}",
        done.spent
    );
    assert!(done.log.is_empty(), "no removed row");
    assert!(
        path.exists(),
        "the root is still there while the call is held"
    );
    drop(hold);
    // The delete was made through a copy of the root's handle, which shares its file object: the
    // name goes when the last of the two handles closes.
    drop(done.root);
    wait_until("the held call ran and removed the root", || !path.exists());
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_delete_call_that_does_not_end_is_given_up_and_no_further_call_is_made_for_the_root() {
    let scratch = Scratch::new();
    let (_run, root, _owner) = made_root(&scratch);
    let tmp = root.tmp();
    // `home` goes first, so that the removal's first delete call is for a file of `tmp`, whatever
    // order the platform lists the root in.
    std::fs::remove_dir(root.home()).unwrap();
    for file in ["a.txt", "b.txt"] {
        std::fs::write(tmp.join(file), b"x").unwrap();
    }
    let name = root.name().clone();
    let hold = removal::hold_deletes(&name);
    let done = remove_on_a_thread(root, LIMITS, Duration::from_secs(30));
    assert_eq!(done.leftovers.len(), 2, "{:?}", done.leftovers);
    let object = &done.leftovers[0];
    assert!(
        ["tmp\\a.txt", "tmp\\b.txt"].contains(&object.path.as_str())
            && object.reason == "the delete call did not end",
        "the object whose call was given up: {object:?}"
    );
    assert_eq!(
        done.leftovers[1],
        Leftover {
            path: String::new(),
            reason: "a delete call did not end".to_owned()
        },
        "and one leftover for the root"
    );
    assert_eq!(removal::cancels(&name), 1);
    assert!(
        done.spent >= LIMITS.wait_each + GRACE && done.spent <= AT_MOST,
        "the removal waited for the limit and the whole grace: {:?}",
        done.spent
    );
    assert_eq!(
        names_in(&tmp),
        ["a.txt", "b.txt"],
        "no further delete call was made, and the held one has not run"
    );
    assert!(
        removal::call_pending(&name),
        "the given-up call is still in the system"
    );
    // A second removal of the root, while the first call is still in the system, makes no delete
    // call, no listing and no cancel, and says why.
    let cancels = removal::cancels(&name);
    let again = remove_on_a_thread(done.root, LIMITS, Duration::from_secs(30));
    assert_eq!(
        again.leftovers,
        [Leftover {
            path: String::new(),
            reason: "a delete call of an earlier removal of this root has not ended".to_owned()
        }]
    );
    assert!(again.spent < Duration::from_secs(1), "{:?}", again.spent);
    assert_eq!(removal::cancels(&name), cancels);
    assert_eq!(names_in(&tmp), ["a.txt", "b.txt"], "nothing was deleted");
    drop(hold);
    wait_until("the given-up call ended", || !removal::call_pending(&name));
    assert_eq!(names_in(&tmp).len(), 1, "the held call removed its object");
    let (rest, _) = remove_with_the_walks_privileges(&again.root);
    assert!(rest.is_empty(), "the next removal finishes: {rest:?}");
    assert!(common::is_gone(again.root), "the root is gone");
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn delete_calls_that_each_end_just_inside_their_limit_spend_the_total_and_stop_the_removal() {
    let scratch = Scratch::new();
    let (_run, root, _owner) = made_root(&scratch);
    let tmp = root.tmp();
    // `home` goes first, so that every delete call the hook slows is for a file of `tmp`.
    std::fs::remove_dir(root.home()).unwrap();
    for index in 0..5 {
        std::fs::write(tmp.join(format!("f{index}.txt")), b"x").unwrap();
    }
    let name = root.name().clone();
    // Each call waits 0.9 seconds and then succeeds, inside the one second a call is given, as a
    // lock holder answers just before the limit. Two calls leave a tenth of the total.
    let delay = removal::delay_deletes(&name, Duration::from_millis(900));
    let done = remove_on_a_thread(root, LIMITS, Duration::from_secs(30));
    assert_eq!(
        done.leftovers,
        [Leftover {
            path: String::new(),
            reason: "the waits for objects in use are spent".to_owned()
        }],
        "the third call took longer than the half second it was given with the total spent, and the removal made no call after it"
    );
    assert!(
        done.spent >= LIMITS.wait_total && done.spent <= AT_MOST,
        "{:?}",
        done.spent
    );
    assert_eq!(
        names_in(&tmp).len(),
        2,
        "three of the five went and two stayed: {:?}",
        names_in(&tmp)
    );
    assert!(done.log.is_empty());
    drop(delay);
    let (rest, _) = remove_with_the_walks_privileges(&done.root);
    assert!(rest.is_empty(), "the next removal finishes: {rest:?}");
    assert!(common::is_gone(done.root), "the root is gone");
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_delete_call_just_over_the_grace_is_charged_whole_against_the_total() {
    let scratch = Scratch::new();
    let (_run, root, _owner) = made_root(&scratch);
    let tmp = root.tmp();
    std::fs::remove_dir(root.home()).unwrap();
    for index in 0..12 {
        std::fs::write(tmp.join(format!("f{index}.txt")), b"x").unwrap();
    }
    let name = root.name().clone();
    // Each call takes about 60 milliseconds, ten more than the 50 an ordinary delete is allowed.
    // Charged whole, about seven of them spend a total of 400 milliseconds; if only what is over
    // the 50 were charged, twelve would cost about 120 and the total would never be spent.
    let delay = removal::delay_deletes(&name, Duration::from_millis(60));
    let limits = Limits {
        wait_each: Duration::from_secs(1),
        wait_total: Duration::from_millis(400),
        ..ROOT_LIMITS
    };
    let done = remove_on_a_thread(root, limits, Duration::from_secs(30));
    assert_eq!(
        done.leftovers,
        [Leftover {
            path: String::new(),
            reason: "the waits for objects in use are spent".to_owned()
        }]
    );
    let removed = 12 - names_in(&tmp).len();
    assert!(
        (4..=8).contains(&removed),
        "the calls were charged whole: {removed} of twelve went before the total was spent"
    );
    drop(delay);
    let (rest, _) = remove_with_the_walks_privileges(&done.root);
    assert!(rest.is_empty(), "the next removal finishes: {rest:?}");
    assert!(common::is_gone(done.root), "the root is gone");
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn the_repairs_open_and_the_recorded_directorys_open_complete_at_once_under_a_lock() {
    let scratch = Scratch::new();
    let directory = scratch.path("locked-dir");
    std::fs::create_dir(&directory).unwrap();
    let hint_dir = scratch.path("hint");
    std::fs::create_dir(&hint_dir).unwrap();
    let key = DirHandle::open_anchor(&directory)
        .unwrap()
        .expect("the directory is accepted")
        .key();
    let hint = DirHandle::open_anchor(&hint_dir)
        .unwrap()
        .expect("the hint is accepted");
    // The holder shares write and delete but not read, so that the two opens, which ask to list,
    // conflict with it; the platform then owes it a break of its handle-caching lock first.
    let lock = Lock::take_sharing(&directory, LOCK_READ | LOCK_HANDLE, 2 | 4);
    let started = Instant::now();
    let repaired = {
        let directory = directory.clone();
        on_a_thread(Duration::from_secs(30), move || {
            let wanted = sd::descriptor(SdKind::AdminDir, &Principals::default()).unwrap();
            acl::set_protected_when_empty(&directory, &wanted)
        })
    };
    let repair_spent = started.elapsed();
    let recorded = on_a_thread(Duration::from_secs(30), move || {
        let started = Instant::now();
        let opened = RecordedDir::open(hint.handle(), &key);
        (opened.map(|_| ()), started.elapsed())
    });
    println!(
        "lock of read and handle: the repair {repaired:?} in {repair_spent:?}, the recorded open {recorded:?}"
    );
    assert_eq!(
        repaired.unwrap_err().code,
        32,
        "the repair's open meets a sharing violation and does not wait for the lock"
    );
    assert!(repair_spent < Duration::from_secs(5), "{repair_spent:?}");
    assert_eq!(
        recorded.0.unwrap_err().code,
        32,
        "the recorded directory's open meets a sharing violation and does not wait for the lock"
    );
    assert!(recorded.1 < Duration::from_secs(5), "{:?}", recorded.1);
    assert!(
        lock.break_was_asked_for(),
        "the lock was asked to give up, or the case shows nothing"
    );
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_listed_object_renamed_by_case_alone_is_a_leftover_and_is_not_removed_under_its_old_name() {
    let scratch = Scratch::new();
    let (_run, root, _owner) = made_root(&scratch);
    let tmp = root.tmp();
    std::fs::write(tmp.join("case-swap.txt"), b"the same object").unwrap();
    {
        let tmp = tmp.clone();
        removal::set(root.name(), move |event| {
            // After the listing and before the open: the object keeps its identity and takes the
            // same name in capitals. The old spelling still opens it.
            if let Event::Listed { directory, .. } = event
                && *directory == "tmp"
            {
                std::fs::rename(tmp.join("case-swap.txt"), tmp.join("CASE-SWAP.TXT")).unwrap();
            }
        });
    }
    let (leftovers, log) = remove_with_the_walks_privileges(&root);
    removal::clear(root.name());
    assert_eq!(
        leftovers,
        [Leftover {
            path: "tmp\\case-swap.txt".to_owned(),
            reason: "the object is no longer directly beneath its directory".to_owned()
        }]
    );
    assert!(log.is_empty(), "no removed row while something is left");
    let names: Vec<String> = std::fs::read_dir(&tmp)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["CASE-SWAP.TXT"], "the object is as it was");
    let (rest, _) = remove_with_the_walks_privileges(&root);
    assert!(
        rest.is_empty(),
        "the next removal lists the new spelling: {rest:?}"
    );
    assert!(common::is_gone(root), "the root is gone");
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_child_made_between_the_empty_check_and_the_change_is_reported_and_not_hidden() {
    let scratch = Scratch::new();
    let wanted = sd::descriptor(SdKind::AdminDir, &Principals::default()).unwrap();
    let directory = scratch.path("raced");
    std::fs::create_dir(&directory).unwrap();
    {
        let directory = directory.clone();
        acl::testing::set_after_check(&directory.clone(), move || {
            std::fs::write(directory.join("late.txt"), b"made in the window").unwrap();
        });
    }
    let result = acl::set_protected_when_empty(&directory, &wanted).unwrap();
    acl::testing::clear(&directory);
    assert_eq!(
        result,
        Reset::NotEmpty,
        "a child that appeared in the window is reported, not hidden"
    );
    assert!(directory.join("late.txt").exists());
    let summary = look_at(&directory).summary;
    assert!(
        summary.protected && summary.entries.as_ref().map(Vec::len) == Some(2),
        "the list was set, which the caller is told by the same answer: {summary:?}"
    );
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn the_token_pipe_and_service_descriptors_built_in_the_descriptor_module_are_the_lists_they_replaced()
 {
    let group = group();
    let person = Sid::parse("S-1-5-21-1-2-3-1001").unwrap();
    let principals = Principals {
        group: Some(group.clone()),
        persons: vec![person.clone()],
        ..Principals::default()
    };
    assert_eq!(
        sd::descriptor_text(SdKind::TokenDefault, &principals).unwrap(),
        format!("D:(A;;GA;;;{})(A;;GA;;;SY)", group.to_text())
    );
    assert_eq!(
        sd::descriptor_text(SdKind::ControlPipe, &principals).unwrap(),
        "D:P(A;;GA;;;SY)(A;;0x120183;;;BA)(A;;0x120183;;;S-1-5-21-1-2-3-1001)"
    );
    assert_eq!(
        sd::descriptor_text(SdKind::Service, &principals).unwrap(),
        "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCLORC;;;S-1-5-21-1-2-3-1001)"
    );
    for kind in [SdKind::TokenDefault, SdKind::ControlPipe, SdKind::Service] {
        assert!(
            sd::descriptor(kind, &principals).is_ok(),
            "the platform reads the {kind:?} descriptor"
        );
    }
    assert!(
        sd::descriptor_text(SdKind::TokenDefault, &Principals::default()).is_err(),
        "the default list needs the group"
    );
}
