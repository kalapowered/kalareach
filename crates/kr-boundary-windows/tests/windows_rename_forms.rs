//! A probe of the platform's forms of a rename through the handle of the file that is renamed. For
//! each form it makes a file through a handle with the rights that a record's replacement is made
//! with, renames it over a record that is there, and prints the call's answer, the structure's size
//! and the name's length that the call passed, and where the new content then stands: in the
//! record's folder, in the process's current directory, or nowhere. It runs only in a disposable
//! Windows guest, as SYSTEM, in a temporary folder that is not the current directory.

#![cfg(windows)]
#![allow(unsafe_code)]

use std::os::windows::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use windows_sys::Wdk::Storage::FileSystem::NtSetInformationFile;
use windows_sys::Win32::Foundation::{
    CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, RtlNtStatusToDosError,
};
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_NEW, CreateFileW, DELETE, FILE_ADD_FILE, FILE_ATTRIBUTE_NORMAL,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_LIST_DIRECTORY, FILE_RENAME_INFO, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, FileRenameInfo, FileRenameInfoEx,
    GetFinalPathNameByHandleW, OPEN_EXISTING, SetFileInformationByHandle, WriteFile,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

const SYNCHRONIZE: u32 = 0x0010_0000;
const REPLACE: u32 = 0x1;
const POSIX: u32 = 0x2;
/// `FileRenameInformation` and `FileRenameInformationEx` of the native call.
const NT_RENAME: i32 = 10;
const NT_RENAME_EX: i32 = 65;

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

fn final_path(handle: HANDLE) -> PathBuf {
    let mut buffer = vec![0_u16; 1024];
    // SAFETY: the buffer lives through the call and its length is given.
    let length =
        unsafe { GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), 1024, 0) } as usize;
    assert!(
        length > 0 && length < 1024,
        "{}",
        std::io::Error::last_os_error()
    );
    PathBuf::from(String::from_utf16_lossy(&buffer[..length]))
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

#[derive(Clone, Copy)]
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

struct Form {
    label: &'static str,
    call: Call,
    flags: u32,
    /// The rights of the folder handle that goes as the root; none: no root handle.
    root: Option<u32>,
    /// The name is the folder's own final path with the record's name, not the bare name.
    absolute: bool,
}

/// Runs one form in a folder of its own and returns the line that says what happened.
fn run(form: &Form, base: &Path) -> String {
    let dir = base.join(form.label);
    std::fs::create_dir(&dir).unwrap();
    let record = dir.join("record.json");
    std::fs::write(&record, b"old").unwrap();
    let staging = dir.join("stage.new");
    let file = staging_file(&staging, b"new");
    let root = form.root.map(|rights| folder(&dir, rights));
    let name_text: Vec<u16> = if form.absolute {
        let held = root.unwrap_or_else(|| folder(&dir, GENERIC_READ));
        wide(&final_path(held).join("record.json"))
            .into_iter()
            .take_while(|unit| *unit != 0)
            .collect()
    } else {
        "record.json".encode_utf16().collect()
    };
    let (buffer, size) = buffer_of(form.flags, root.unwrap_or(std::ptr::null_mut()), &name_text);
    let answer = match form.call {
        Call::Plain | Call::Ex => {
            let class = if matches!(form.call, Call::Ex) {
                FileRenameInfoEx
            } else {
                FileRenameInfo
            };
            // SAFETY: the handle is open and the buffer holds the structure of the class, of the size given.
            let done =
                unsafe { SetFileInformationByHandle(file, class, buffer.as_ptr().cast(), size) };
            if done == 0 {
                format!(
                    "error {}",
                    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
                )
            } else {
                "ok".to_owned()
            }
        }
        Call::NtPlain | Call::NtEx => {
            let class = if matches!(form.call, Call::NtEx) {
                NT_RENAME_EX
            } else {
                NT_RENAME
            };
            let mut block = IO_STATUS_BLOCK::default();
            // SAFETY: as above; the status block lives through the call.
            let status = unsafe {
                NtSetInformationFile(file, &raw mut block, buffer.as_ptr().cast(), size, class)
            };
            if status >= 0 {
                "ok".to_owned()
            } else {
                // SAFETY: converts a status the platform just returned.
                format!("status {status:#010x} = error {}", unsafe {
                    RtlNtStatusToDosError(status)
                })
            }
        }
    };
    let in_folder = match std::fs::read(&record) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(_) => "missing".to_owned(),
    };
    let current = std::env::current_dir().unwrap().join("record.json");
    let in_current = current.exists();
    if in_current {
        let _ = std::fs::remove_file(&current);
    }
    let left = staging.exists();
    // SAFETY: the handles were opened above and are closed once.
    unsafe {
        CloseHandle(file);
        if let Some(root) = root {
            CloseHandle(root);
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    format!(
        "FORM {:<14} {:<7} flags {} root {:<9} name {:<8} size {} namelen {}: {answer}; record in its folder: {in_folder}; record in the current directory: {in_current}; staging file left: {left}",
        form.label,
        match form.call {
            Call::Plain => "plain",
            Call::Ex => "ex",
            Call::NtPlain => "nt",
            Call::NtEx => "nt-ex",
        },
        form.flags,
        match form.root {
            None => "none",
            Some(rights) if rights == GENERIC_READ => "read",
            Some(_) => "add",
        },
        if form.absolute { "absolute" } else { "bare" },
        size,
        name_text.len() * 2,
    )
}

#[test]
#[ignore = "needs a disposable Windows guest, as SYSTEM (see windows_install.rs)"]
fn the_forms_of_a_rename_through_the_handle_of_the_renamed_file_are_tried() {
    const ADD: u32 = FILE_LIST_DIRECTORY | FILE_ADD_FILE | FILE_TRAVERSE | SYNCHRONIZE;
    let id = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let base = std::env::temp_dir().join(format!("krforms-{id}"));
    let current = std::env::temp_dir().join(format!("krcurrent-{id}"));
    std::fs::create_dir(&base).unwrap();
    std::fs::create_dir(&current).unwrap();
    std::env::set_current_dir(&current).unwrap();
    println!(
        "FORMS base {} current directory {}",
        base.display(),
        current.display()
    );
    let forms = [
        Form {
            label: "a-ex-read",
            call: Call::Ex,
            flags: REPLACE | POSIX,
            root: Some(GENERIC_READ),
            absolute: false,
        },
        Form {
            label: "a2-ex-replace",
            call: Call::Ex,
            flags: REPLACE,
            root: Some(GENERIC_READ),
            absolute: false,
        },
        Form {
            label: "b-plain-read",
            call: Call::Plain,
            flags: REPLACE,
            root: Some(GENERIC_READ),
            absolute: false,
        },
        Form {
            label: "c1-ex-add",
            call: Call::Ex,
            flags: REPLACE | POSIX,
            root: Some(ADD),
            absolute: false,
        },
        Form {
            label: "c2-ex-add-r",
            call: Call::Ex,
            flags: REPLACE,
            root: Some(ADD),
            absolute: false,
        },
        Form {
            label: "c3-plain-add",
            call: Call::Plain,
            flags: REPLACE,
            root: Some(ADD),
            absolute: false,
        },
        Form {
            label: "d1-ex-abs",
            call: Call::Ex,
            flags: REPLACE | POSIX,
            root: None,
            absolute: true,
        },
        Form {
            label: "d2-plain-abs",
            call: Call::Plain,
            flags: REPLACE,
            root: None,
            absolute: true,
        },
        Form {
            label: "e1-nt-read",
            call: Call::NtPlain,
            flags: REPLACE,
            root: Some(GENERIC_READ),
            absolute: false,
        },
        Form {
            label: "e2-ntex-read",
            call: Call::NtEx,
            flags: REPLACE | POSIX,
            root: Some(GENERIC_READ),
            absolute: false,
        },
        Form {
            label: "e3-nt-add",
            call: Call::NtPlain,
            flags: REPLACE,
            root: Some(ADD),
            absolute: false,
        },
        Form {
            label: "e4-ntex-add",
            call: Call::NtEx,
            flags: REPLACE | POSIX,
            root: Some(ADD),
            absolute: false,
        },
    ];
    for form in &forms {
        println!("{}", run(form, &base));
    }
    std::env::set_current_dir(std::env::temp_dir()).unwrap();
    let _ = std::fs::remove_dir_all(&base);
    let _ = std::fs::remove_dir_all(&current);
}
