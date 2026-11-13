//! The platform's answers that the record's rename rests on. For each form it makes a file through
//! a handle with the rights that a record's replacement is made with, renames it over a record that
//! is there, and reads the call's answer and where the new content then stands: in the record's
//! folder, in the process's current directory, or nowhere. The native call with the held folder's
//! handle as the root and a bare name replaces the record in that folder and leaves nothing in the
//! current directory; the Win32 call refuses every form with a root handle. A later change of
//! either answer meets a red case. The cases run only in a disposable Windows guest, as SYSTEM, in a
//! temporary folder that is not the current directory.

#![cfg(windows)]
#![allow(unsafe_code)]

use std::os::windows::ffi::OsStrExt as _;
use std::path::Path;
use std::sync::{Mutex, PoisonError};

use windows_sys::Wdk::Storage::FileSystem::NtSetInformationFile;
use windows_sys::Win32::Foundation::{
    CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, RtlNtStatusToDosError,
};
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_NEW, CreateFileW, DELETE, FILE_ADD_FILE, FILE_ATTRIBUTE_NORMAL,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_LIST_DIRECTORY, FILE_RENAME_INFO, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, FileRenameInfo, FileRenameInfoEx,
    OPEN_EXISTING, SetFileInformationByHandle, WriteFile,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

const SYNCHRONIZE: u32 = 0x0010_0000;
const REPLACE: u32 = 0x1;
const POSIX: u32 = 0x2;
/// `FileRenameInformation` and `FileRenameInformationEx` of the native call.
const NT_RENAME: i32 = 10;
const NT_RENAME_EX: i32 = 65;
/// The rights of a folder handle that may add a file to its folder.
const ADD: u32 = FILE_LIST_DIRECTORY | FILE_ADD_FILE | FILE_TRAVERSE | SYNCHRONIZE;
/// The Win32 error of "the parameter is incorrect".
const INVALID_PARAMETER: u32 = 87;

/// Every case of this program changes the process's current directory, which is the process's own:
/// one case runs at a time.
static SERIAL: Mutex<()> = Mutex::new(());

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

/// A file made new through a handle with the right to delete it, which shares read only, as a
/// record's replacement is, holding the text.
fn staging_file(path: &Path, text: &[u8]) -> HANDLE {
    let name = wide(path);
    // SAFETY: the name is NUL-terminated and lives through the call.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE | DELETE,
            FILE_SHARE_READ,
            std::ptr::null(),
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    assert_ne!(
        handle,
        INVALID_HANDLE_VALUE,
        "{}",
        std::io::Error::last_os_error()
    );
    let mut written = 0_u32;
    // SAFETY: the handle is open for writing and the buffer lives through the call.
    let done = unsafe {
        WriteFile(
            handle,
            text.as_ptr(),
            text.len() as u32,
            &raw mut written,
            std::ptr::null_mut(),
        )
    };
    assert_ne!(done, 0, "{}", std::io::Error::last_os_error());
    handle
}

/// The folder opened with the given rights, sharing everything.
fn folder(path: &Path, access: u32) -> HANDLE {
    let name = wide(path);
    // SAFETY: the name is NUL-terminated and lives through the call.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    assert_ne!(
        handle,
        INVALID_HANDLE_VALUE,
        "{}",
        std::io::Error::last_os_error()
    );
    handle
}

/// The structure that both calls take: flags (or the replace byte), the root directory, the name.
fn buffer_of(flags: u32, root: HANDLE, name: &[u16]) -> (Vec<u64>, u32) {
    let header = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
    let size = header + name.len() * 2;
    let mut buffer = vec![0_u64; size.div_ceil(8)];
    let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    // SAFETY: the buffer is aligned for the structure and holds it and the name behind the header.
    unsafe {
        (*info).Anonymous.Flags = flags;
        (*info).RootDirectory = root;
        (*info).FileNameLength = (name.len() * 2) as u32;
        std::ptr::copy_nonoverlapping(
            name.as_ptr(),
            (&raw mut (*info).FileName).cast::<u16>(),
            name.len(),
        );
    }
    (buffer, size as u32)
}

#[derive(Clone, Copy, Debug)]
enum Call {
    /// `SetFileInformationByHandle`, class `FileRenameInfo`.
    Plain,
    /// `SetFileInformationByHandle`, class `FileRenameInfoEx`.
    Ex,
    /// `NtSetInformationFile`, `FileRenameInformation`.
    NtPlain,
    /// `NtSetInformationFile`, `FileRenameInformationEx`.
    NtEx,
}

/// What one rename did.
#[derive(Debug)]
struct Outcome {
    /// The platform's error code when the call was refused.
    refused: Option<u32>,
    /// What the record's name holds in its folder afterwards.
    in_folder: String,
    /// Whether a file named like the record stands in the process's current directory.
    in_current: bool,
    /// Whether the file that was renamed still stands under its own name.
    staging_left: bool,
}

/// Renames a new file over a record in a folder of its own, by the given call and flags, with a
/// handle of that folder opened with `root_rights` as the root and the bare name, while the
/// process's current directory is another folder.
fn attempt(call: Call, flags: u32, root_rights: u32) -> Outcome {
    let _one_at_a_time = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let id = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let base = std::env::temp_dir().join(format!("krrename-{id}"));
    let elsewhere = std::env::temp_dir().join(format!("krcurrent-{id}"));
    let dir = base.join("folder");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::create_dir(&elsewhere).unwrap();
    std::env::set_current_dir(&elsewhere).unwrap();
    let record = dir.join("record.json");
    std::fs::write(&record, b"old").unwrap();
    let staging = dir.join("stage.new");
    let file = staging_file(&staging, b"new");
    let root = folder(&dir, root_rights);
    let name: Vec<u16> = "record.json".encode_utf16().collect();
    let (buffer, size) = buffer_of(flags, root, &name);
    let refused = match call {
        Call::Plain | Call::Ex => {
            let class = if matches!(call, Call::Ex) {
                FileRenameInfoEx
            } else {
                FileRenameInfo
            };
            // SAFETY: the handle is open and the buffer holds the structure of the class, of the size given.
            let done =
                unsafe { SetFileInformationByHandle(file, class, buffer.as_ptr().cast(), size) };
            (done == 0).then(|| {
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .map_or(u32::MAX, |code| code as u32)
            })
        }
        Call::NtPlain | Call::NtEx => {
            let class = if matches!(call, Call::NtEx) {
                NT_RENAME_EX
            } else {
                NT_RENAME
            };
            let mut block = IO_STATUS_BLOCK::default();
            // SAFETY: as above; the status block lives through the call.
            let status = unsafe {
                NtSetInformationFile(file, &raw mut block, buffer.as_ptr().cast(), size, class)
            };
            // SAFETY: converts a status the platform just returned.
            (status < 0).then(|| unsafe { RtlNtStatusToDosError(status) })
        }
    };
    let in_folder = std::fs::read(&record).map_or_else(
        |_| "missing".to_owned(),
        |bytes| String::from_utf8_lossy(&bytes).into_owned(),
    );
    let in_current = elsewhere.join("record.json").exists();
    let staging_left = staging.exists();
    // SAFETY: the handles were opened above and are closed once.
    unsafe {
        CloseHandle(file);
        CloseHandle(root);
    }
    std::env::set_current_dir(std::env::temp_dir()).unwrap();
    let _ = std::fs::remove_dir_all(&base);
    let _ = std::fs::remove_dir_all(&elsewhere);
    Outcome {
        refused,
        in_folder,
        in_current,
        staging_left,
    }
}

#[test]
#[ignore = "needs a disposable Windows guest, as SYSTEM (see windows_install.rs)"]
fn the_native_rename_with_a_held_directorys_handle_and_a_bare_name_replaces_the_record_in_that_directory()
 {
    for (call, flags, rights) in [
        (Call::NtPlain, REPLACE, GENERIC_READ),
        (Call::NtPlain, REPLACE, ADD),
        (Call::NtEx, REPLACE | POSIX, GENERIC_READ),
        (Call::NtEx, REPLACE | POSIX, ADD),
    ] {
        let outcome = attempt(call, flags, rights);
        let form = format!("{call:?}, flags {flags}, root rights {rights:#x}: {outcome:?}");
        assert_eq!(outcome.refused, None, "the call was refused: {form}");
        assert_eq!(
            outcome.in_folder, "new",
            "the record in the handle's folder is not the new content: {form}"
        );
        assert!(
            !outcome.in_current,
            "a file stands in the current directory: {form}"
        );
        assert!(
            !outcome.staging_left,
            "the renamed file still stands under its own name: {form}"
        );
    }
}

#[test]
#[ignore = "needs a disposable Windows guest, as SYSTEM (see windows_install.rs)"]
fn the_win32_rename_with_any_root_handle_is_refused_and_changes_nothing() {
    for (call, flags, rights) in [
        (Call::Plain, REPLACE, GENERIC_READ),
        (Call::Plain, REPLACE, ADD),
        (Call::Ex, REPLACE, GENERIC_READ),
        (Call::Ex, REPLACE, ADD),
        (Call::Ex, REPLACE | POSIX, GENERIC_READ),
        (Call::Ex, REPLACE | POSIX, ADD),
    ] {
        let outcome = attempt(call, flags, rights);
        let form = format!("{call:?}, flags {flags}, root rights {rights:#x}: {outcome:?}");
        assert_eq!(
            outcome.refused,
            Some(INVALID_PARAMETER),
            "the call was not refused with error 87: {form}"
        );
        assert_eq!(
            outcome.in_folder, "old",
            "the record in the handle's folder changed: {form}"
        );
        assert!(
            !outcome.in_current,
            "a file stands in the current directory: {form}"
        );
        assert!(
            outcome.staging_left,
            "the renamed file does not stand under its own name: {form}"
        );
    }
}
