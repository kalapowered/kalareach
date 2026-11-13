//! A probe of the platform's forms of taking away an object that a run made, through the handle of
//! the call that made it. For a directory made relative to its parent's held handle, and for a file
//! made relative to a directory's held handle, each made with no right to delete and sharing
//! everything, it prints what the platform answers to: a reopen of the object's own handle with the
//! right to delete, and an open of the object by its bare name relative to the parent's handle with
//! the right to delete, followed by the comparison of the two identities and the removal mark on
//! the handle of that open. It runs only in a disposable Windows guest, as SYSTEM, in a temporary
//! folder.

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

/// What the two forms answer for one object that was made through `identity_handle` relative to
/// `parent`, named `name` there, at `path`.
fn forms_for(
    what: &str,
    parent: HANDLE,
    name: &str,
    identity_handle: HANDLE,
    path: &Path,
    directory: bool,
) {
    let made = identity(identity_handle);
    match reopen(identity_handle) {
        Ok(again) => {
            println!(
                "REMOVAL {what}: ReOpenFile with DELETE | FILE_READ_ATTRIBUTES: ok; identity {} the made object's",
                if identity(again) == made {
                    "equals"
                } else {
                    "differs from"
                }
            );
            // SAFETY: the handle was just opened.
            unsafe { CloseHandle(again) };
        }
        Err(error) => {
            println!("REMOVAL {what}: ReOpenFile with DELETE | FILE_READ_ATTRIBUTES: {error}")
        }
    }
    match open_by_name(parent, name, DELETE, FILE_OPEN, directory) {
        Ok(opened) => {
            let same = identity(opened) == made;
            let marked = mark(opened);
            let gone_at_mark = !path.exists();
            // SAFETY: the handle was just opened.
            unsafe { CloseHandle(opened) };
            println!(
                "REMOVAL {what}: open by bare name relative to the parent's handle with DELETE: ok; identity {} the made object's; mark for removal: {marked}; path gone right after the mark: {gone_at_mark}; gone after the close: {}",
                if same { "equals" } else { "differs from" },
                !path.exists()
            );
        }
        Err(error) => println!(
            "REMOVAL {what}: open by bare name relative to the parent's handle with DELETE: {error}"
        ),
    }
}

#[test]
#[ignore = "needs a disposable Windows guest, as SYSTEM (see windows_install.rs)"]
fn the_forms_of_taking_away_what_a_run_made_through_its_handles_are_tried() {
    let id = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let top = std::env::temp_dir().join(format!("krremoval-{id}"));
    std::fs::create_dir(&top).unwrap();

    // A directory made relative to its parent's handle, with the rights that the installation's
    // handles carry: listing and the right to change the list, and no right to delete.
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
    forms_for("a directory", parent, "made", made, &top.join("made"), true);

    // A file made relative to a directory's handle that may add a file.
    std::fs::create_dir(top.join("holder")).unwrap();
    let holder = folder(
        &top.join("holder"),
        FILE_LIST_DIRECTORY | FILE_ADD_FILE | FILE_TRAVERSE | SYNCHRONIZE,
    );
    let file = open_by_name(holder, "record.json", FILE_WRITE_DATA, FILE_CREATE, false)
        .expect("the file is made");
    forms_for(
        "a file",
        holder,
        "record.json",
        file,
        &top.join("holder").join("record.json"),
        false,
    );

    // SAFETY: the handles were opened above and are closed once.
    unsafe {
        CloseHandle(file);
        CloseHandle(holder);
        CloseHandle(made);
        CloseHandle(parent);
    }
    let _ = std::fs::remove_dir_all(&top);
}
