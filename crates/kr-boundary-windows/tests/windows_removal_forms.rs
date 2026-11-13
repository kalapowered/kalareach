//! The platform's answers that the removal of an object that a run made rests on. For a directory
//! made relative to its parent's held handle, and for a file made relative to a directory's held
//! handle, each made with no right to delete and sharing everything, the cases read what the
//! platform answers to a reopen of the object's own handle with the right to delete (refused for a
//! directory) and to an open of the object by its bare name relative to the parent's handle with the
//! right to delete (the same object, which the removal mark on that handle takes away when the
//! handle is closed). A later change of either answer meets a red case. The cases run only in a
//! disposable Windows guest, as SYSTEM, in a temporary folder.

#![cfg(windows)]
#![allow(unsafe_code)]

use std::os::windows::ffi::OsStrExt as _;
use std::path::Path;

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_FOR_BACKUP_INTENT,
    FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, HANDLE, INVALID_HANDLE_VALUE, RtlNtStatusToDosError, UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, DELETE, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_NORMAL, FILE_DISPOSITION_INFO_EX, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, FileDispositionInfoEx,
    FileIdInfo, GetFileInformationByHandleEx, OPEN_EXISTING, ReOpenFile,
    SetFileInformationByHandle,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

const SYNCHRONIZE: u32 = 0x0010_0000;
const READ_CONTROL: u32 = 0x0002_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const FILE_WRITE_DATA: u32 = 0x2;
const FILE_NON_DIRECTORY_FILE: u32 = 0x40;
const FILE_SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

/// A folder opened by its path with the given rights, sharing everything.
fn folder(path: &Path, access: u32) -> HANDLE {
    let name = wide(path);
    // SAFETY: the name is NUL-terminated and lives through the call.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            access,
            FILE_SHARE_ALL,
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

/// The call that the installation makes an object with: relative to the parent's handle, by a bare
/// name, sharing everything, with the rights given and the reparse point opened as it is.
fn open_by_name(
    parent: HANDLE,
    name: &str,
    access: u32,
    disposition: u32,
    directory: bool,
) -> Result<HANDLE, String> {
    let units: Vec<u16> = name.encode_utf16().collect();
    let text = UNICODE_STRING {
        Length: (units.len() * 2) as u16,
        MaximumLength: (units.len() * 2) as u16,
        Buffer: units.as_ptr().cast_mut(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent,
        ObjectName: &raw const text,
        Attributes: 0,
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut raw: HANDLE = std::ptr::null_mut();
    let mut block = IO_STATUS_BLOCK::default();
    // SAFETY: the name, the attributes and the status block live through the call, and the
    // parent's handle is open.
    let status = unsafe {
        NtCreateFile(
            &raw mut raw,
            access | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
            &raw const attributes,
            &raw mut block,
            std::ptr::null(),
            if directory {
                FILE_ATTRIBUTE_DIRECTORY
            } else {
                FILE_ATTRIBUTE_NORMAL
            },
            FILE_SHARE_ALL,
            disposition,
            (if directory {
                FILE_DIRECTORY_FILE
            } else {
                FILE_NON_DIRECTORY_FILE
            }) | FILE_OPEN_REPARSE_POINT
                | FILE_OPEN_FOR_BACKUP_INTENT
                | FILE_SYNCHRONOUS_IO_NONALERT,
            std::ptr::null(),
            0,
        )
    };
    if status < 0 {
        // SAFETY: converts a status the platform just returned.
        Err(format!("status {status:#010x} = error {}", unsafe {
            RtlNtStatusToDosError(status)
        }))
    } else {
        Ok(raw)
    }
}

/// The volume and the file identifier that the handle's object has.
fn identity(handle: HANDLE) -> String {
    let mut info = FILE_ID_INFO::default();
    // SAFETY: the handle is open and the structure is the one that the class takes.
    let done = unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            (&raw mut info).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    };
    if done == 0 {
        return format!("unread (error {})", std::io::Error::last_os_error());
    }
    format!(
        "{:x}:{:x?}",
        info.VolumeSerialNumber, info.FileId.Identifier
    )
}

/// The mark for removal with the delete flag and POSIX semantics, as the cleanup sets it.
fn mark(handle: HANDLE) -> String {
    let info = FILE_DISPOSITION_INFO_EX { Flags: 0x3 };
    // SAFETY: the handle is open and the structure is the one that the class takes.
    let done = unsafe {
        SetFileInformationByHandle(
            handle,
            FileDispositionInfoEx,
            (&raw const info).cast(),
            size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        )
    };
    if done == 0 {
        format!(
            "error {}",
            std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        )
    } else {
        "ok".to_owned()
    }
}

/// The reopen of the object's own handle with the right to delete, as the cleanup asks it.
fn reopen(handle: HANDLE) -> Result<HANDLE, String> {
    // SAFETY: the handle is open.
    let reopened = unsafe {
        ReOpenFile(
            handle,
            DELETE | FILE_READ_ATTRIBUTES,
            FILE_SHARE_ALL,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        )
    };
    if reopened == INVALID_HANDLE_VALUE {
        Err(format!(
            "error {}",
            std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        ))
    } else {
        Ok(reopened)
    }
}

/// What the two forms answered for one object that was made through `identity_handle` relative to
/// `parent`, named `name` there, at `path`.
#[derive(Debug)]
struct Forms {
    /// The answer to the reopen of the object's own handle with the right to delete.
    reopen: String,
    /// The answer to the open by the bare name relative to the parent's handle with the right to
    /// delete.
    open_by_name: String,
    /// Whether the object that that open reached has the identity of the object that was made.
    same_identity: bool,
    /// The answer to the removal mark on the handle of that open.
    mark: String,
    /// Whether the name still answered right after the mark, with the made object's own handle open.
    present_after_the_mark: bool,
    /// Whether the name still answered after the handle of that open was closed.
    present_after_the_close: bool,
}

fn forms_for(
    parent: HANDLE,
    name: &str,
    identity_handle: HANDLE,
    path: &Path,
    directory: bool,
) -> Forms {
    let made = identity(identity_handle);
    let reopen = match reopen(identity_handle) {
        Ok(again) => {
            // SAFETY: the handle was just opened.
            unsafe { CloseHandle(again) };
            "ok".to_owned()
        }
        Err(error) => error,
    };
    match open_by_name(parent, name, DELETE, FILE_OPEN, directory) {
        Ok(opened) => {
            let same_identity = identity(opened) == made;
            let mark = mark(opened);
            let present_after_the_mark = path.exists();
            // SAFETY: the handle was just opened.
            unsafe { CloseHandle(opened) };
            Forms {
                reopen,
                open_by_name: "ok".to_owned(),
                same_identity,
                mark,
                present_after_the_mark,
                present_after_the_close: path.exists(),
            }
        }
        Err(error) => Forms {
            reopen,
            open_by_name: error,
            same_identity: false,
            mark: "not tried".to_owned(),
            present_after_the_mark: path.exists(),
            present_after_the_close: path.exists(),
        },
    }
}

/// A folder of its own in the temporary directory.
fn scratch_folder(label: &str) -> std::path::PathBuf {
    let id = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let top = std::env::temp_dir().join(format!("krremoval-{label}-{id}"));
    std::fs::create_dir(&top).unwrap();
    top
}

/// The forms for a directory made relative to its parent's handle, with the rights that the
/// installation's handles carry: listing and the right to change the list, and no right to delete.
fn forms_for_a_made_directory() -> Forms {
    let top = scratch_folder("directory");
    let parent = folder(
        &top,
        FILE_LIST_DIRECTORY | FILE_ADD_SUBDIRECTORY | SYNCHRONIZE,
    );
    let made = open_by_name(
        parent,
        "made",
        FILE_LIST_DIRECTORY | WRITE_DAC,
        FILE_CREATE,
        true,
    )
    .expect("the directory is made");
    let forms = forms_for(parent, "made", made, &top.join("made"), true);
    // SAFETY: the handles were opened above and are closed once.
    unsafe {
        CloseHandle(made);
        CloseHandle(parent);
    }
    let _ = std::fs::remove_dir_all(&top);
    forms
}

/// The forms for a file made relative to the handle of a directory that may add a file.
fn forms_for_a_made_file() -> Forms {
    let top = scratch_folder("file");
    let holder = folder(
        &top,
        FILE_LIST_DIRECTORY | FILE_ADD_FILE | FILE_TRAVERSE | SYNCHRONIZE,
    );
    let file = open_by_name(holder, "record.json", FILE_WRITE_DATA, FILE_CREATE, false)
        .expect("the file is made");
    let forms = forms_for(holder, "record.json", file, &top.join("record.json"), false);
    // SAFETY: the handles were opened above and are closed once.
    unsafe {
        CloseHandle(file);
        CloseHandle(holder);
    }
    let _ = std::fs::remove_dir_all(&top);
    forms
}

#[test]
#[ignore = "needs a disposable Windows guest, as SYSTEM (see windows_install.rs)"]
fn the_reopen_of_a_made_directory_with_the_right_to_delete_is_refused() {
    let forms = forms_for_a_made_directory();
    assert_eq!(
        forms.reopen, "error 5",
        "the reopen of a directory's own handle with DELETE was not refused with access denied: {forms:?}"
    );
}

#[test]
#[ignore = "needs a disposable Windows guest, as SYSTEM (see windows_install.rs)"]
fn a_made_directory_and_a_made_file_are_removed_through_a_delete_open_relative_to_their_parent() {
    for (what, forms) in [
        ("directory", forms_for_a_made_directory()),
        ("file", forms_for_a_made_file()),
    ] {
        assert_eq!(
            forms.open_by_name, "ok",
            "the open of the {what} by its bare name relative to the parent's handle with DELETE failed: {forms:?}"
        );
        assert!(
            forms.same_identity,
            "the {what} that the open reached is not the object that was made: {forms:?}"
        );
        assert_eq!(
            forms.mark, "ok",
            "the removal mark on the handle of the open failed for the {what}: {forms:?}"
        );
        assert!(
            forms.present_after_the_mark,
            "the {what} was gone while another handle to it was open: {forms:?}"
        );
        assert!(
            !forms.present_after_the_close,
            "the {what} stands after the handle that marked it was closed: {forms:?}"
        );
    }
}
