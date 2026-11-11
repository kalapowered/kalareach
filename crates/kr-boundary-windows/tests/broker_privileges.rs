//! What the privilege guard does, and what the backup and restore privileges are enough for, shown
//! on a Windows guest.
//!
//! These cases run only in a disposable guest, as SYSTEM, under a Hyper-V checkpoint that is
//! restored afterwards. The process token holds the two privileges disabled; a walk enables them on
//! a copy of that token that only its own thread uses, and the thread has nothing once the guard is
//! gone. The last case runs the removal of a private root full of hostile objects with every subset
//! of the three privileges that could matter, and shows the least set that is enough.

#![cfg(all(windows, feature = "testing"))]
#![allow(unsafe_code)]

mod common;

use std::ffi::c_void;
use std::marker::PhantomData;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, GENERIC_READ, HANDLE, LUID};
use windows_sys::Win32::Security::{
    GetTokenInformation, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
    TOKEN_PRIVILEGES, TOKEN_QUERY, TokenPrivileges,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_READ, OPEN_EXISTING,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
};

use kr_boundary_windows::win::ffi::{Handle, wide, wide_path};
use kr_boundary_windows::win::privilege::{self, PrivGuard, Privilege};
use kr_boundary_windows::win::root::{create_root, remove_root};

use common::{Rows, Scratch, group, hostile_dir, hostile_file, run_dir};

/// Whether a token holds a privilege and has it enabled: `None` when it does not hold it.
fn state_in(token: HANDLE, name: &str) -> Option<bool> {
    let mut luid = LUID {
        LowPart: 0,
        HighPart: 0,
    };
    let wide_name = wide(name);
    // SAFETY: the name is NUL-terminated and the out-parameter is local.
    assert_ne!(
        unsafe { LookupPrivilegeValueW(null(), wide_name.as_ptr(), &raw mut luid) },
        0
    );
    let mut size = 0_u32;
    // SAFETY: asks for the size only.
    unsafe {
        GetTokenInformation(token, TokenPrivileges, null_mut(), 0, &raw mut size);
    }
    let mut buffer = vec![0_u64; (size as usize).div_ceil(8)];
    // SAFETY: the buffer is at least `size` bytes.
    assert_ne!(
        unsafe {
            GetTokenInformation(
                token,
                TokenPrivileges,
                buffer.as_mut_ptr().cast::<c_void>(),
                size,
                &raw mut size,
            )
        },
        0
    );
    // SAFETY: the buffer holds a TOKEN_PRIVILEGES: a count and that many entries.
    let privileges = unsafe { &*buffer.as_ptr().cast::<TOKEN_PRIVILEGES>() };
    // SAFETY: the entries follow the count and there are `PrivilegeCount` of them.
    let entries: &[LUID_AND_ATTRIBUTES] = unsafe {
        std::slice::from_raw_parts(
            privileges.Privileges.as_ptr(),
            privileges.PrivilegeCount as usize,
        )
    };
    entries
        .iter()
        .find(|entry| entry.Luid.LowPart == luid.LowPart && entry.Luid.HighPart == luid.HighPart)
        .map(|entry| entry.Attributes & SE_PRIVILEGE_ENABLED != 0)
}

fn process_state(name: &str) -> Option<bool> {
    let mut token: HANDLE = null_mut();
    // SAFETY: the pseudo-handle of the current process is valid and the out-parameter is local.
    assert_ne!(
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) },
        0
    );
    let token = Handle::new(token, "the process token").unwrap();
    state_in(token.raw(), name)
}

fn thread_state(name: &str) -> Option<Option<bool>> {
    let mut token: HANDLE = null_mut();
    // SAFETY: the pseudo-handle of the current thread is valid and the out-parameter is local.
    let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &raw mut token) };
    if opened == 0 {
        return None;
    }
    let token = Handle::new(token, "the thread token").unwrap();
    Some(state_in(token.raw(), name))
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn the_process_token_never_has_the_privileges_enabled_and_the_walks_thread_does_for_the_length_of_a_guard()
 {
    for name in ["SeBackupPrivilege", "SeRestorePrivilege"] {
        assert_eq!(
            process_state(name),
            Some(false),
            "{name} is held and disabled on the process token before a walk"
        );
    }
    assert!(
        !privilege::thread_has_token(),
        "the thread starts with no token of its own"
    );
    {
        let guard = privilege::enter().expect("the privileges can be enabled");
        for name in ["SeBackupPrivilege", "SeRestorePrivilege"] {
            assert_eq!(
                process_state(name),
                Some(false),
                "{name} stays disabled on the process token during a walk"
            );
            assert_eq!(
                thread_state(name),
                Some(Some(true)),
                "{name} is enabled on the walking thread's own token"
            );
        }
        assert_eq!(
            thread_state("SeTakeOwnershipPrivilege"),
            Some(Some(false)),
            "the privilege that is held back is not enabled with the pair"
        );
        drop(guard);
    }
    assert!(
        !privilege::thread_has_token(),
        "the thread has no token after the guard"
    );
    for name in ["SeBackupPrivilege", "SeRestorePrivilege"] {
        assert_eq!(
            process_state(name),
            Some(false),
            "{name} stays disabled on the process token after a walk"
        );
    }
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_second_thread_cannot_open_an_object_that_refuses_the_system_while_a_walk_runs() {
    let scratch = Scratch::new();
    let owner = group();
    let file = scratch.path("hostile.txt");
    common::privileged(|| hostile_file(&file, &owner, b"x"));
    let open = |path: std::path::PathBuf| -> Result<(), u32> {
        let wide = wide_path(&path);
        // SAFETY: the path is NUL-terminated.
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                null_mut(),
            )
        };
        Handle::new(raw, "the hostile file")
            .map(|_| ())
            .map_err(|error| error.code)
    };
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
    let walking = {
        let file = file.clone();
        std::thread::spawn(move || {
            let guard = privilege::enter().unwrap();
            let own = open(file);
            ready_tx.send(()).unwrap();
            done_rx.recv().unwrap();
            drop(guard);
            own
        })
    };
    ready_rx.recv().unwrap();
    let other = std::thread::spawn({
        let file = file.clone();
        move || open(file)
    })
    .join()
    .unwrap();
    done_tx.send(()).unwrap();
    assert_eq!(
        walking.join().unwrap(),
        Ok(()),
        "the walking thread opens it"
    );
    assert_eq!(
        other,
        Err(ERROR_ACCESS_DENIED),
        "another thread of the same process is refused while the walk runs"
    );
    let after = open(file);
    assert_eq!(
        after,
        Err(ERROR_ACCESS_DENIED),
        "and it is refused after the walk, too"
    );
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_walk_that_fails_or_panics_leaves_its_thread_without_the_token() {
    let failed = || -> Result<(), &'static str> {
        let _guard = privilege::enter().unwrap();
        assert!(privilege::thread_has_token());
        Err("a forced error")
    };
    assert!(failed().is_err());
    assert!(
        !privilege::thread_has_token(),
        "an error returns the thread to its own token"
    );
    let panicked = catch_unwind(AssertUnwindSafe(|| {
        let _guard = privilege::enter().unwrap();
        panic!("a forced panic");
    }));
    assert!(panicked.is_err());
    assert!(
        !privilege::thread_has_token(),
        "a panic returns the thread to its own token"
    );
    drop(privilege::enter().expect("and the thread can walk again"));
    assert!(
        privilege::enter().is_ok() && !privilege::revert_failed(),
        "no failure was recorded"
    );
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_revert_that_fails_poisons_the_thread_and_stops_the_service() {
    std::thread::spawn(|| {
        assert!(!privilege::revert_failed());
        privilege::testing::fail_next_revert();
        drop(privilege::enter().unwrap());
        assert!(
            privilege::revert_failed(),
            "the service is told to stop accepting requests"
        );
        assert!(
            privilege::enter().is_err(),
            "the thread runs no further walk, and neither does another"
        );
        privilege::testing::clear();
        assert!(!privilege::revert_failed());
    })
    .join()
    .unwrap();
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_guard_cannot_be_started_inside_another_on_the_same_thread() {
    let guard = privilege::enter().unwrap();
    assert!(
        privilege::enter().is_err(),
        "a second guard would replace the first one's token"
    );
    drop(guard);
    assert!(privilege::enter().is_ok());
}

/// The guard stays on its thread: the compiler refuses to send it, which this line shows by
/// failing to compile when `PrivGuard` is `Send`.
const _: () = {
    trait AmbiguousIfSend<A> {
        fn some_item() {}
    }
    impl<T: ?Sized> AmbiguousIfSend<()> for T {}
    impl<T: ?Sized + Send> AmbiguousIfSend<u8> for T {}
    let _ = <PrivGuard as AmbiguousIfSend<_>>::some_item;
    let _: PhantomData<PrivGuard> = PhantomData;
};

/// Every subset of the three privileges, as a name and a list.
fn subsets() -> Vec<(String, Vec<Privilege>)> {
    let all = [
        Privilege::Backup,
        Privilege::Restore,
        Privilege::TakeOwnership,
    ];
    (0_u8..8)
        .map(|mask| {
            let picked: Vec<Privilege> = all
                .iter()
                .enumerate()
                .filter(|(index, _)| mask & (1 << index) != 0)
                .map(|(_, privilege)| *privilege)
                .collect();
            (format!("{picked:?}"), picked)
        })
        .collect()
}

/// Builds a private root with a hostile file, a read-only hostile file and a hostile directory of
/// the same kind that holds one, each owned by the invocation's group, listing the group alone and
/// refusing the system.
fn root_with_hostile_objects(
    scratch: &Scratch,
) -> (common::Run, kr_boundary_windows::win::root::PrivateRoot) {
    let run = run_dir(scratch);
    let owner = group();
    let mut rows = Rows::default();
    let root = create_root(&run.dir, &run.path, &owner, &mut rows).expect("the root is made");
    common::privileged(|| {
        hostile_file(&root.tmp().join("file.txt"), &owner, b"bytes");
        hostile_file(&root.tmp().join("readonly.txt"), &owner, b"bytes");
        let mut permissions = std::fs::metadata(root.tmp().join("readonly.txt"))
            .unwrap()
            .permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(root.tmp().join("readonly.txt"), permissions).unwrap();
        hostile_dir(&root.home().join("directory"), &owner);
        hostile_file(
            &root.home().join("directory").join("inside.txt"),
            &owner,
            b"bytes",
        );
    });
    (run, root)
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn the_least_set_of_privileges_that_removes_a_root_of_hostile_objects_is_backup_and_restore() {
    let mut table = Vec::new();
    for (name, subset) in subsets() {
        let scratch = Scratch::new();
        let (_run, root) = root_with_hostile_objects(&scratch);
        let guard = privilege::enter_with(&subset).expect("the subset can be enabled");
        let mut rows = Rows::default();
        let leftovers = remove_root(&root, &guard, &mut rows).expect("the removal runs");
        drop(guard);
        let gone = !root.path().exists();
        table.push((name.clone(), leftovers.len(), gone));
        println!(
            "privileges {name}: {} leftover(s), root removed: {gone}",
            leftovers.len()
        );
        if !gone {
            // A root that stays is removed with the full pair so that the folder can be cleaned.
            let guard = privilege::enter().unwrap();
            let mut rows = Rows::default();
            let _ = remove_root(&root, &guard, &mut rows);
        }
    }
    let works = |wanted: &str| table.iter().find(|(name, _, _)| name == wanted).unwrap().2;
    assert!(
        works("[Backup, Restore]"),
        "backup and restore remove every hostile object"
    );
    assert!(
        !works("[]"),
        "with no privilege a hostile object stays, so the privileges are needed"
    );
    let sufficient: Vec<&str> = table
        .iter()
        .filter(|(_, _, gone)| *gone)
        .map(|(name, _, _)| name.as_str())
        .collect();
    println!("subsets that removed every hostile object: {sufficient:?}");
}
