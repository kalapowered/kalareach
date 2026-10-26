//! The store of releases on Windows: what the operating system is asked for where the Unix store
//! asks for a symbolic link, a file lock and a file mode.
//!
//! | Unix | Windows |
//! | --- | --- |
//! | `current` is a relative symbolic link, replaced by renaming a new one over it | `current` is a directory junction, replaced by renaming a new junction over it in one step ([`replace_directory`]) |
//! | a program holds a shared `flock` on its release's manifest | a program holds its release's manifest open for reading with a share mode that allows no write and no delete ([`open_for_hold`]), which keeps the release's directory from being renamed or removed |
//! | whether a release is held is asked by trying an exclusive `flock` | by trying to open the manifest with a share mode that allows nothing ([`is_held`]) |
//! | a sealed release is mode `0444`/`0555` | a sealed release is read-only by attribute and carries an access-control list that gives its owner read access and nothing that writes ([`seal_file`], [`seal_directory`]) |
//!
//! A program's image is asked from the kernel with `QueryFullProcessImageNameW`, which names the
//! file the process was created from after a junction on the way was followed, and so is the
//! release's own file whatever `current` names afterwards. The path the process was started as,
//! which the standard library reports, is the one through `current`.

#![expect(
    unsafe_code,
    reason = "a junction is made and replaced, a process's image is named and a file's identity and \
              access-control list are read and set through calls that have no safe interface"
)]

use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_OPEN_FOR_BACKUP_INTENT, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT, NtOpenFile,
};
use windows_sys::Wdk::System::SystemServices::RtlGetVersion;
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_FILES, ERROR_SHARING_VIOLATION,
    HANDLE, LocalFree, OBJ_DONT_REPARSE, RtlNtStatusToDosError, STATUS_DELETE_PENDING,
    STATUS_SUCCESS, UNICODE_STRING,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACCESS_DENIED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SetKernelObjectSecurity,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DISPOSITION_FLAG_DELETE,
    FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE, FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
    FILE_DISPOSITION_INFO_EX, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_ID_BOTH_DIR_INFO, FILE_ID_INFO, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES,
    FILE_RENAME_INFO, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_DISK,
    FILE_WRITE_ATTRIBUTES, FileDispositionInfoEx, FileIdBothDirectoryInfo,
    FileIdBothDirectoryRestartInfo, FileIdInfo, FileRenameInfoEx, GetDiskFreeSpaceExW,
    GetFileInformationByHandleEx, GetFileType, GetVolumeInformationW, GetVolumePathNameW,
    READ_CONTROL, SYNCHRONIZE, SetFileInformationByHandle, WRITE_DAC,
};
use windows_sys::Win32::System::IO::{DeviceIoControl, IO_STATUS_BLOCK};
use windows_sys::Win32::System::Ioctl::FSCTL_SET_REPARSE_POINT;
use windows_sys::Win32::System::SystemInformation::OSVERSIONINFOW;
use windows_sys::Win32::System::SystemServices::ACCESS_DENIED_ACE_TYPE;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, PROCESS_NAME_WIN32, QueryFullProcessImageNameW,
};
use windows_sys::Win32::System::WindowsProgramming::{
    FILE_RENAME_FLAG_POSIX_SEMANTICS, FILE_RENAME_FLAG_REPLACE_IF_EXISTS,
};

/// The tag of a directory junction, the reparse point `mklink /J` makes.
const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;

/// The share mode of a handle that lets every other handle read, write and delete.
const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

/// Reads this process's own image from the kernel: the file the process was created from, with
/// every junction and link on the way it was started through resolved.
///
/// # Errors
///
/// Returns the operating system's error when it does not say.
pub(super) fn image_path() -> io::Result<PathBuf> {
    let mut capacity = 512_u32;
    loop {
        let mut buffer = vec![0_u16; capacity as usize];
        let mut size = capacity;
        // SAFETY: the current process pseudo-handle is always valid, `buffer` holds `size` code
        // units, and `size` is a live in-out parameter the call updates to the length it wrote.
        let named = unsafe {
            QueryFullProcessImageNameW(
                GetCurrentProcess(),
                PROCESS_NAME_WIN32,
                buffer.as_mut_ptr(),
                &raw mut size,
            )
        };
        if named != 0 {
            buffer.truncate(size as usize);
            return Ok(PathBuf::from(OsString::from_wide(&buffer)));
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_INSUFFICIENT_BUFFER.cast_signed())
            && capacity < 65_536
        {
            capacity *= 2;
            continue;
        }
        return Err(error);
    }
}

/// Whether `error` says another handle's share mode, or this one's, keeps the open from being
/// granted.
pub(super) fn is_sharing_violation(error: &io::Error) -> bool {
    error.raw_os_error() == Some(ERROR_SHARING_VIOLATION.cast_signed())
}

/// Whether `error` is what renaming a directory answers while a handle on something inside it
/// allows no delete, or while nothing of this account lets it be moved. The two are told apart by
/// nothing the operating system says, so a caller treats both as "not now".
pub(super) fn is_in_use(error: &io::Error) -> bool {
    is_sharing_violation(error) || error.raw_os_error() == Some(ERROR_ACCESS_DENIED.cast_signed())
}

/// Opens a file for reading with the given share mode, without following a link, and checks that
/// it is a regular file on a disk: a junction or a link planted under a release's name would
/// otherwise turn a read into a read of something else, and a device name would open a device.
///
/// # Errors
///
/// Returns the operating system's error, [`io::ErrorKind::NotFound`] among them, and an error of
/// kind `InvalidData` for a link and for anything but a regular file.
fn open_reading(path: &Path, share: u32) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .share_mode(share)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let about = file.metadata()?;
    if about.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "it is a link, and no file of a release is",
        ));
    }
    // SAFETY: the handle is the open file's own and stays open for the call.
    let kind = unsafe { GetFileType(file.as_raw_handle()) };
    if !about.is_file() || kind != FILE_TYPE_DISK {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "it is not a regular file",
        ));
    }
    Ok(file)
}

/// How long a read of a file of a release waits for a question whether the release is held
/// ([`is_held`]), which opens the manifest with no sharing for an instant.
const QUESTION_WAIT: Duration = Duration::from_secs(2);

/// Opens a file of a release for reading without following a link, letting every other handle
/// read, write and delete.
///
/// A sharing violation is waited out for [`QUESTION_WAIT`]: the only handle that causes one is the
/// instant of the question whether the release is held, so a reader is never refused by it.
///
/// # Errors
///
/// As [`open_reading`], and the sharing violation itself once the wait has passed.
pub(super) fn open_regular_file(path: &Path) -> io::Result<File> {
    let deadline = Instant::now() + QUESTION_WAIT;
    loop {
        match open_reading(path, SHARE_ALL) {
            Err(error) if is_sharing_violation(&error) && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            answer => return answer,
        }
    }
}

/// Opens a release's manifest to hold the release: for reading, with a share mode that allows other
/// handles to read and nothing else. While the handle is open the manifest cannot be renamed,
/// replaced or deleted, nor can the directory it is in or any directory above it up to the store's
/// `versions`, which is what keeps a release from being removed under a program that runs from it.
///
/// A sharing violation is waited out for up to `within`, because it is also what a check of
/// whether the release is held ([`is_held`]) causes for as long as it lasts, which is an instant.
///
/// # Errors
///
/// Returns the operating system's error, [`io::ErrorKind::NotFound`] among them, and the sharing
/// violation itself once `within` has passed.
pub(super) fn open_for_hold(path: &Path, within: Duration) -> io::Result<File> {
    let deadline = Instant::now() + within;
    loop {
        match open_reading(path, FILE_SHARE_READ) {
            Err(error) if is_sharing_violation(&error) && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            answer => return answer,
        }
    }
}

/// Whether anything holds the release whose manifest is at `path`: whether the manifest can be
/// opened for reading by a handle that allows no other handle to it at all. Every holder has it
/// open for reading, so one is a sharing violation.
///
/// The handle lives for the length of the call. A holder that opens the manifest in that moment is
/// refused with a sharing violation and tries again ([`open_for_hold`]).
///
/// # Errors
///
/// Returns the operating system's error when the manifest cannot be opened for any reason but a
/// holder.
pub(super) fn is_held(path: &Path) -> io::Result<bool> {
    match open_reading(path, 0) {
        Ok(_) => Ok(false),
        Err(error) if is_sharing_violation(&error) => Ok(true),
        Err(error) => Err(error),
    }
}

/// A file's identity: the volume and the number the volume gives it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct FileIdentity {
    volume: u64,
    file: [u8; 16],
}

/// Reads the identity of the file or directory a handle is open on.
///
/// # Errors
///
/// Returns the operating system's error when it does not say.
pub(super) fn identity(file: &File) -> io::Result<FileIdentity> {
    let mut information = FILE_ID_INFO {
        VolumeSerialNumber: 0,
        FileId: Default::default(),
    };
    // SAFETY: the handle is the open file's own, and `information` is a live buffer of exactly the
    // size of the structure the class asks for.
    let read = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            (&raw mut information).cast(),
            u32::try_from(size_of::<FILE_ID_INFO>()).unwrap_or(0),
        )
    };
    if read == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(FileIdentity {
        volume: information.VolumeSerialNumber,
        file: information.FileId.Identifier,
    })
}

/// Opens a file or a directory only to read its identity, without following a link.
fn open_for_identity(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .access_mode(windows_sys::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES)
        .share_mode(SHARE_ALL)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

/// Whether two paths name one file or directory, whatever spelling each has: case, a short name,
/// a verbatim prefix. A path that cannot be opened is none.
pub(super) fn same_object(one: &Path, other: &Path) -> bool {
    let (Ok(one), Ok(other)) = (open_for_identity(one), open_for_identity(other)) else {
        return false;
    };
    matches!((identity(&one), identity(&other)), (Ok(a), Ok(b)) if a == b)
}

/// Whether the file system `path` is on is NTFS, the one a store is kept on.
///
/// # Errors
///
/// Returns the operating system's error when the volume cannot be named or asked.
pub(super) fn is_ntfs(path: &Path) -> io::Result<bool> {
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    let mut root = vec![0_u16; 1024];
    // SAFETY: `wide` is null-terminated, and `root` holds the number of code units the call is
    // told it may write.
    let named = unsafe {
        GetVolumePathNameW(
            wide.as_ptr(),
            root.as_mut_ptr(),
            u32::try_from(root.len()).unwrap_or(0),
        )
    };
    if named == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut name = [0_u16; 64];
    // SAFETY: `root` was written null-terminated by the call above, `name` is the file system
    // name buffer with its length, and the other outputs are not asked for.
    let asked = unsafe {
        GetVolumeInformationW(
            root.as_ptr(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            name.as_mut_ptr(),
            u32::try_from(name.len()).unwrap_or(0),
        )
    };
    if asked == 0 {
        return Err(io::Error::last_os_error());
    }
    let length = name
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(name.len());
    Ok(OsString::from_wide(&name[..length]) == OsStr::new("NTFS"))
}

/// The path as the junction's substitute name spells it: the NT form, `\??\C:\...`.
fn nt_path(path: &Path) -> io::Result<Vec<u16>> {
    let absolute = std::path::absolute(path)?;
    let text: Vec<u16> = absolute.as_os_str().encode_wide().collect();
    let units = |text: &str| text.encode_utf16().collect::<Vec<u16>>();
    let local_drive = |rest: &[u16]| {
        rest.get(1) == Some(&u16::from(b':'))
            && rest.first().is_some_and(|unit| {
                u8::try_from(*unit).is_ok_and(|byte| byte.is_ascii_alphabetic())
            })
    };
    let rest = text
        .strip_prefix(units(r"\\?\").as_slice())
        .unwrap_or(&text);
    if !local_drive(rest) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a junction names a place on a local drive, not a network path",
        ));
    }
    let mut name = units(r"\??\");
    name.extend_from_slice(rest);
    while name.last() == Some(&u16::from(b'\\')) && name.len() > 7 {
        name.pop();
    }
    Ok(name)
}

/// Makes a directory junction at `link` that names the directory `target`.
///
/// `link` must not exist. A junction's target is an absolute path, so it names the place it was
/// made for and no other.
///
/// # Errors
///
/// Returns the operating system's error when the directory cannot be made or the junction cannot
/// be set on it, and then leaves no directory behind.
pub(super) fn create_junction(link: &Path, target: &Path) -> io::Result<()> {
    let data = junction_data(target)?;
    std::fs::create_dir(link)?;
    let set = set_junction(link, &data);
    if set.is_err() {
        let _ = std::fs::remove_dir(link);
    }
    set
}

/// The reparse data of a junction that names the directory `target`.
fn junction_data(target: &Path) -> io::Result<Vec<u8>> {
    let substitute = nt_path(target)?;
    // The print name is the target as a person reads it, without the NT prefix.
    let print = substitute[4..].to_vec();
    let (substitute_bytes, print_bytes) = (substitute.len() * 2, print.len() * 2);
    // Four 16-bit offsets and lengths, then the two names, each with its own terminator.
    let data_length = 8 + substitute_bytes + 2 + print_bytes + 2;
    let Ok(data_length_field) = u16::try_from(data_length) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the target's path is too long for a junction",
        ));
    };
    let mut buffer = Vec::with_capacity(8 + data_length);
    buffer.extend_from_slice(&IO_REPARSE_TAG_MOUNT_POINT.to_le_bytes());
    buffer.extend_from_slice(&data_length_field.to_le_bytes());
    buffer.extend_from_slice(&0_u16.to_le_bytes());
    // The sizes below fit the 16-bit fields because the whole data length does.
    let to_field = |bytes: usize| u16::try_from(bytes).unwrap_or(0).to_le_bytes();
    buffer.extend_from_slice(&0_u16.to_le_bytes());
    buffer.extend_from_slice(&to_field(substitute_bytes));
    buffer.extend_from_slice(&to_field(substitute_bytes + 2));
    buffer.extend_from_slice(&to_field(print_bytes));
    for unit in substitute.iter().chain(&[0]).chain(&print).chain(&[0]) {
        buffer.extend_from_slice(&unit.to_le_bytes());
    }
    Ok(buffer)
}

/// Makes the empty directory `link` a junction with the reparse data `data`.
fn set_junction(link: &Path, data: &[u8]) -> io::Result<()> {
    let directory = OpenOptions::new()
        .write(true)
        .share_mode(SHARE_ALL)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(link)?;
    let mut returned = 0_u32;
    // SAFETY: the handle is the open directory's own, `data` holds the reparse data it is told,
    // and no output buffer is asked for.
    let done = unsafe {
        DeviceIoControl(
            directory.as_raw_handle(),
            FSCTL_SET_REPARSE_POINT,
            data.as_ptr().cast(),
            u32::try_from(data.len()).unwrap_or(0),
            std::ptr::null_mut(),
            0,
            &raw mut returned,
            std::ptr::null_mut(),
        )
    };
    if done == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Makes the existing empty directory `directory` a junction that names `target`, as another
/// process of the account can while a removal has the directory open.
///
/// # Errors
///
/// Returns the operating system's error when the junction cannot be set.
#[cfg(feature = "testing")]
pub(super) fn make_junction_in_place(directory: &Path, target: &Path) -> io::Result<()> {
    set_junction(directory, &junction_data(target)?)
}

/// Renames the directory or junction `from` to `to`, replacing a directory or junction that is
/// named `to`, in one step: a program that opens `to` meanwhile finds the old one or the new one
/// whole and never neither.
///
/// The standard library's rename replaces a directory only through a fall-back after the first
/// attempt fails, so this asks for what is wanted: the file system's own rename with its flags
/// to replace what is there and to follow the rules a POSIX rename follows.
///
/// # Errors
///
/// Returns the operating system's error when `from` cannot be opened or the rename is refused.
pub(super) fn replace_directory(from: &Path, to: &Path) -> io::Result<()> {
    let source = OpenOptions::new()
        .access_mode(DELETE)
        .share_mode(SHARE_ALL)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(from)?;
    let name: Vec<u16> = std::path::absolute(to)?.as_os_str().encode_wide().collect();
    let name_bytes = u32::try_from(name.len() * 2)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "the path is too long"))?;
    // The record ends in its name, which is not terminated, so the buffer is the record's size up
    // to the name and the name; a buffer of 64-bit words is aligned for the record.
    let name_at = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
    let total = name_at + name.len() * 2 + 2;
    let mut buffer = vec![0_u64; total.div_ceil(8)];
    let record = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    // SAFETY: `buffer` is zeroed, aligned for the record and at least `total` bytes long, so the
    // fixed fields are inside it, and the name's bytes end inside it; nothing else reads it until
    // the call below.
    unsafe {
        (*record).Anonymous.Flags =
            FILE_RENAME_FLAG_REPLACE_IF_EXISTS | FILE_RENAME_FLAG_POSIX_SEMANTICS;
        (*record).RootDirectory = std::ptr::null_mut();
        (*record).FileNameLength = name_bytes;
        std::ptr::copy_nonoverlapping(
            name.as_ptr().cast::<u8>(),
            buffer.as_mut_ptr().cast::<u8>().add(name_at),
            name.len() * 2,
        );
    }
    // SAFETY: the handle is the open source's own, and `buffer` holds a rename record of `total`
    // bytes with its name inside.
    let renamed = unsafe {
        SetFileInformationByHandle(
            source.as_raw_handle(),
            FileRenameInfoEx,
            buffer.as_ptr().cast(),
            u32::try_from(total).unwrap_or(0),
        )
    };
    if renamed == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Runs `body` with this process refusing to be ended by a console interrupt, so that Ctrl+C and
/// Ctrl+Break reach only a child that shares the console and not the parent that waits for it.
///
/// A handler is installed, never the process-wide "ignore" flag, because that flag is inherited by
/// the children the process starts, which would then ignore the interrupt as well.
pub(super) fn while_interrupts_go_to_the_child<T>(body: impl FnOnce() -> T) -> T {
    use windows_sys::Win32::System::Console::{
        CTRL_BREAK_EVENT, CTRL_C_EVENT, SetConsoleCtrlHandler,
    };

    unsafe extern "system" fn handler(kind: u32) -> i32 {
        i32::from(kind == CTRL_C_EVENT || kind == CTRL_BREAK_EVENT)
    }
    // SAFETY: the handler is a function with the signature the call asks for, and lives for the
    // whole program.
    let installed = unsafe { SetConsoleCtrlHandler(Some(handler), 1) } != 0;
    let answer = body();
    if installed {
        // SAFETY: removes the handler added above.
        unsafe {
            SetConsoleCtrlHandler(Some(handler), 0);
        }
    }
    answer
}

/// What a sealed file or directory lets its owner do: read it, list it, run it, and change its
/// access-control list so as to unseal it. Nothing here writes, appends, deletes or adds a name.
const OWNER_MAY: u32 = 0x0000_0001 // read data, list a directory
    | 0x0000_0008 // read extended attributes
    | 0x0000_0020 // execute, traverse a directory
    | 0x0000_0080 // read attributes
    | READ_CONTROL
    | WRITE_DAC
    | 0x0010_0000; // synchronise

/// What nothing may do to a sealed file or directory: write data or add a file, append or add a
/// directory, write extended attributes, delete a name in a directory, write attributes, delete.
const NOTHING_MAY: u32 = 0x0000_0002 // write data, add a file
    | 0x0000_0004 // append, add a subdirectory
    | 0x0000_0010 // write extended attributes
    | 0x0000_0040 // delete a name in a directory
    | 0x0000_0100 // write attributes
    | 0x0001_0000; // delete

/// What the system and the administrators may do to a sealed file or directory: read and run it.
const OTHERS_MAY_READ: u32 =
    0x0000_0001 | 0x0000_0008 | 0x0000_0020 | 0x0000_0080 | READ_CONTROL | 0x0010_0000;

/// What an unsealed directory is given back: everything, to its owner.
const OWNER_ONLY: &str = "D:P(A;;GA;;;OW)(A;;GA;;;SY)";

/// Sets an explicit, protected access-control list, written as SDDL, on the file or directory at
/// `path` itself, never on what a link there leads to, and on nothing else.
///
/// The list is set on the object alone: `SetSecurityInfo` and `SetNamedSecurityInfo` pass a
/// changed list down to the objects inside a directory and take the entries they inherited from
/// those that carry them, and a file inside a release can be a hard link to a file elsewhere, whose
/// own list would be emptied by it. The kernel's call changes the one object.
fn set_list(path: &Path, sddl: &str) -> io::Result<()> {
    set_list_on(&open_name(path, WRITE_DAC | READ_CONTROL, SHARE_ALL)?, sddl)
}

/// Sets the list of the object `handle` is open on, as [`set_list`] does. The handle was opened with
/// the right to change the list.
fn set_list_on(handle: &File, sddl: &str) -> io::Result<()> {
    let wide: Vec<u16> = sddl.encode_utf16().chain([0]).collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `wide` is null-terminated and outlives the call, and `descriptor` is a live out
    // parameter; the size is not asked for.
    let parsed = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide.as_ptr(),
            SDDL_REVISION_1,
            &raw mut descriptor,
            std::ptr::null_mut(),
        )
    };
    if parsed == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the handle is the open object's own and was opened with the right to change its
    // list, and `descriptor` is the self-relative descriptor just built, freed after the call.
    let set = unsafe {
        SetKernelObjectSecurity(
            handle.as_raw_handle(),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor,
        )
    };
    let result = if set == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    };
    // SAFETY: `descriptor` was allocated by the conversion above and is freed exactly once.
    unsafe {
        LocalFree(descriptor.cast());
    }
    result
}

/// The access-control list of a sealed file or directory, as SDDL.
fn sealed_list(directory: bool) -> String {
    let nothing = if directory {
        NOTHING_MAY
    } else {
        NOTHING_MAY & !0x40
    };
    format!(
        "D:P(D;;0x{nothing:x};;;OW)(A;;0x{OWNER_MAY:x};;;OW)(A;;0x{OTHERS_MAY_READ:x};;;SY)(A;;0x{OTHERS_MAY_READ:x};;;BA)"
    )
}

/// Seals a file: read-only by attribute, and with an access-control list that gives its owner
/// read access and nothing that writes, appends, deletes or changes its attributes.
///
/// # Errors
///
/// Returns the operating system's error when the file cannot be changed.
pub fn seal_file(path: &Path) -> io::Result<()> {
    let mut permissions = std::fs::metadata(path)?.permissions();
    permissions.set_readonly(true);
    std::fs::set_permissions(path, permissions)?;
    set_list(path, &sealed_list(false))
}

/// Seals a directory: an access-control list that gives its owner read access and nothing that adds
/// a name, removes one or changes the directory.
///
/// # Errors
///
/// Returns the operating system's error when the directory cannot be changed.
pub fn seal_directory(path: &Path) -> io::Result<()> {
    set_list(path, &sealed_list(true))
}

/// Gives a sealed directory back to its owner whole, so that what is in it can be deleted.
///
/// # Errors
///
/// Returns the operating system's error when the directory cannot be changed.
pub fn unseal_directory(path: &Path) -> io::Result<()> {
    set_list(path, OWNER_ONLY)
}

/// What a removal could not remove, told apart by the reason. A program that runs from a file or
/// holds one open without sharing its delete is a reason to try again later; any other refusal is a
/// fault that is reported, and the first of those is the one a removal answers with.
#[derive(Default)]
struct Left {
    held: Option<io::Error>,
    refused: Option<io::Error>,
}

impl Left {
    fn add(&mut self, error: io::Error) {
        let slot = if is_in_use(&error) {
            &mut self.held
        } else {
            &mut self.refused
        };
        slot.get_or_insert(error);
    }

    fn into_result(self) -> io::Result<()> {
        self.refused.or(self.held).map_or(Ok(()), Err)
    }
}

/// What a test runs at the one moment a removal can be raced: right after a directory was pinned
/// and checked, before its names are read.
#[cfg(feature = "testing")]
pub(super) static AFTER_PIN: std::sync::Mutex<Option<PinHook>> = std::sync::Mutex::new(None);

/// What a test runs, with the pinned directory's path.
#[cfg(feature = "testing")]
pub(super) type PinHook = std::sync::Arc<dyn Fn(&Path) + Send + Sync>;

#[cfg(feature = "testing")]
fn after_pin(directory: &Path) {
    let hook = AFTER_PIN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    if let Some(hook) = hook {
        hook(directory);
    }
}

#[cfg(not(feature = "testing"))]
fn after_pin(_directory: &Path) {}

/// A failure that is not a program's hold: the operating system's code is left out of it, so that
/// nothing takes it for one.
fn refused(what: &str, path: &Path, error: &io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{what} {}: {error}", path.display()))
}

/// Deletes the tree at `root`, a release that was sealed or one that was only staged, whole: every
/// directory is given back to its owner before its names are read, every file is deleted as a
/// name, and what a program still runs from is left where it is. Everything else in the tree is
/// deleted either way, so that one program keeps no more than its own files.
///
/// A link, a junction above all, is a name like a file: it is taken away and what it leads to is
/// neither followed nor changed. A file that is a second name for a file outside the tree goes as a
/// name; the file keeps its contents, its attributes and its access list, unless that list is the
/// seal's own, which [`remove_name`] gives back to its owner.
///
/// # Errors
///
/// Returns the operating system's error when a program has a file open or runs from it
/// ([`is_in_use`] holds for it), and otherwise the first refusal, which no program caused.
pub(super) fn remove_tree(root: &Path) -> io::Result<()> {
    if !std::fs::symlink_metadata(root)?.file_type().is_dir() {
        return remove_name(Reach::Path(root), root);
    }
    let mut left = Left::default();
    remove_directory(Reach::Path(root), root, &mut left);
    left.into_result()
}

/// How a name to remove is reached: by its path, which only the root of a walk is, or as a name
/// directly inside a directory held open, which is every other name.
#[derive(Clone, Copy)]
enum Reach<'a> {
    Path(&'a Path),
    Inside(&'a File, &'a [u16]),
}

impl Reach<'_> {
    /// Opens the name itself, never what a link there leads to.
    ///
    /// # Errors
    ///
    /// Returns the operating system's error, [`io::ErrorKind::NotFound`] among them for a name that
    /// is not there or whose removal is already pending.
    fn open(self, access: u32, share: u32) -> io::Result<File> {
        match self {
            Self::Path(path) => open_name(path, access, share),
            Self::Inside(directory, name) => open_inside(directory, name, access, share),
        }
    }
}

/// Deletes what is in the directory `reach` names and then the directory. `shown` is the path to
/// say in a refusal. Returns whether the directory is gone.
///
/// The directory is pinned first: it is opened with a share mode that lets nobody rename or delete
/// it, which holds the directory and every one above it where they are while the handle is open.
/// Nothing is then done by a path. The names in it are read through the pinned handle and each is
/// opened as a name inside that handle, with reparse points not followed, so a directory that
/// another process of the account turns into a junction after it was checked (the share mode does
/// not stop that) has a listing of its own, which is empty, and goes as a name; a name that is
/// swapped for a junction after it was listed is opened as the junction itself and goes as a name.
/// What a junction leads to is never reached.
fn remove_directory(reach: Reach<'_>, shown: &Path, left: &mut Left) -> bool {
    let pin = match reach.open(
        FILE_LIST_DIRECTORY | READ_CONTROL | WRITE_DAC | DELETE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
    ) {
        Ok(pin) => pin,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return true,
        Err(error) if is_sharing_violation(&error) => {
            left.add(error);
            return false;
        }
        Err(error) => {
            left.add(refused("cannot open", shown, &error));
            return false;
        }
    };
    match pin.metadata() {
        Ok(about)
            if about.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0
                && about.file_attributes() & FILE_ATTRIBUTE_DIRECTORY != 0 => {}
        Ok(_) => {
            // Not the directory the caller saw: a link now, which goes as a name.
            return mark_for_deletion(&pin)
                .map_err(|error| left.add(error))
                .is_ok();
        }
        Err(error) => {
            left.add(refused("cannot read", shown, &error));
            return false;
        }
    }
    // Given back to its owner before its names are read: a sealed directory refuses to lose one.
    if let Err(error) = set_list_on(&pin, OWNER_ONLY) {
        left.add(refused("cannot give back", shown, &error));
        return false;
    }
    after_pin(shown);
    let mut emptied = true;
    let mut restart = true;
    loop {
        let names = match list_next(&pin, restart) {
            Ok(Some(names)) => names,
            Ok(None) => break,
            Err(error) => {
                left.add(refused("cannot read", shown, &error));
                return false;
            }
        };
        restart = false;
        for listed in names {
            let inside = shown.join(OsString::from_wide(&listed.name));
            let reach = Reach::Inside(&pin, &listed.name);
            emptied &= if listed.directory {
                remove_directory(reach, &inside, left)
            } else {
                remove_name(reach, &inside)
                    .map_err(|error| left.add(error))
                    .is_ok()
            };
        }
    }
    if !emptied {
        return false;
    }
    mark_for_deletion(&pin)
        .map_err(|error| left.add(error))
        .is_ok()
}

/// A name found in a directory, and whether it is a plain directory: not a link of any kind.
struct Listed {
    name: Vec<u16>,
    directory: bool,
}

/// The bytes of one listing of a directory.
const LISTING_BYTES: usize = 16 * 1024;

/// Reads the next names in the directory `handle` is open on, as many as one listing holds, or
/// from its start when `restart` is set. Returns `None` at the end. The directory's own entries
/// `.` and `..` are left out.
fn list_next(handle: &File, restart: bool) -> io::Result<Option<Vec<Listed>>> {
    // A buffer of 64-bit words is aligned for the records.
    let mut buffer = vec![0_u64; LISTING_BYTES / size_of::<u64>()];
    let class = if restart {
        FileIdBothDirectoryRestartInfo
    } else {
        FileIdBothDirectoryInfo
    };
    // SAFETY: the handle is the open directory's own, opened to list it, and `buffer` holds the
    // number of bytes the call is told.
    let read = unsafe {
        GetFileInformationByHandleEx(
            handle.as_raw_handle(),
            class,
            buffer.as_mut_ptr().cast(),
            u32::try_from(LISTING_BYTES).unwrap_or(0),
        )
    };
    if read == 0 {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(ERROR_NO_MORE_FILES.cast_signed()) {
            Ok(None)
        } else {
            Err(error)
        };
    }
    let bytes = buffer.as_ptr().cast::<u8>();
    let name_at = std::mem::offset_of!(FILE_ID_BOTH_DIR_INFO, FileName);
    let mut names = Vec::new();
    let mut at = 0_usize;
    loop {
        if at + name_at > LISTING_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the system listed a name beyond its own buffer",
            ));
        }
        // SAFETY: the record starts inside `buffer`, which the system filled with whole records,
        // and only fields before the name are read, each as it lies and without a reference.
        let (next, attributes, length) = unsafe {
            let record = bytes.add(at).cast::<FILE_ID_BOTH_DIR_INFO>();
            (
                (&raw const (*record).NextEntryOffset).read_unaligned() as usize,
                (&raw const (*record).FileAttributes).read_unaligned(),
                (&raw const (*record).FileNameLength).read_unaligned() as usize,
            )
        };
        if at + name_at + length > LISTING_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the system listed a name beyond its own buffer",
            ));
        }
        let mut name = vec![0_u16; length / 2];
        // SAFETY: the name's `length` bytes lie inside `buffer`, as checked above, and `name`
        // holds as many.
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.add(at + name_at),
                name.as_mut_ptr().cast::<u8>(),
                name.len() * 2,
            );
        }
        let dots = |count: usize| name.len() == count && name.iter().all(|unit| *unit == 0x2e);
        if !dots(1) && !dots(2) {
            names.push(Listed {
                name,
                directory: attributes & FILE_ATTRIBUTE_DIRECTORY != 0
                    && attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0,
            });
        }
        if next == 0 {
            return Ok(Some(names));
        }
        at += next;
    }
}

/// Deletes the name `reach` reaches: a file, or a link, whose target is neither followed nor
/// changed. `shown` is the path to say in a refusal. The file's own attributes are not cleared; a
/// read-only file is deleted by the system's rule for a handle that asks for it, so that a name of
/// a file that other names share leaves the file as it was.
///
/// Deleting a read-only file asks for the right to change attributes, and the entries the seal puts
/// on a file deny its owner that right. A refusal is therefore either the seal or a program that
/// runs from the file, and the right is asked for to tell which. When the list denies it and begins
/// with the seal's own entry, the file is given back to its owner, the one change to a file's
/// access list a removal makes, and the delete is tried again. A list that denies the right and is
/// not the seal's is somebody else's, and it is left as it is and reported.
///
/// # Errors
///
/// Returns the operating system's error for a program that runs from the file, which
/// [`is_in_use`] knows, and an error without that code for any other refusal.
fn remove_name(reach: Reach<'_>, shown: &Path) -> io::Result<()> {
    let denied =
        |error: &io::Error| error.raw_os_error() == Some(ERROR_ACCESS_DENIED.cast_signed());
    match delete_name(reach) {
        Err(error) if denied(&error) => {
            match reach.open(FILE_WRITE_ATTRIBUTES, SHARE_ALL) {
                Ok(_) => return Err(error),
                Err(not_allowed) if denied(&not_allowed) => {}
                Err(other) => return Err(refused("cannot reach", shown, &other)),
            }
            let sealed = reach
                .open(READ_CONTROL | WRITE_DAC, SHARE_ALL)
                .map_err(|error| refused("cannot give back", shown, &error))?;
            if !begins_with_the_seals_entry(&sealed)
                .map_err(|error| refused("cannot read the list of", shown, &error))?
            {
                return Err(refused(
                    "its list denies the right to delete and is not the seal's:",
                    shown,
                    &error,
                ));
            }
            set_list_on(&sealed, OWNER_ONLY)
                .map_err(|error| refused("cannot give back", shown, &error))?;
            delete_name(reach)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        done => done,
    }
}

/// The SID of the owner-rights principal, `S-1-3-4`, as the bytes an entry carries it in.
const OWNER_RIGHTS_SID: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 3, 4, 0, 0, 0];

/// Whether the access list of the open file begins with the entry the seal puts first: one that
/// denies the owner-rights principal the right to write attributes. The handle was opened with the
/// right to read the list.
fn begins_with_the_seals_entry(file: &File) -> io::Result<bool> {
    let mut list: *mut ACL = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: the handle is the open file's own, and `list` and `descriptor` are live out
    // parameters; the descriptor owns the list and is freed after its last use below.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut list,
            std::ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status.cast_signed()));
    }
    let mut first: *mut std::ffi::c_void = std::ptr::null_mut();
    // SAFETY: `list` is the file's list, which `descriptor` keeps alive, and the entry is read
    // only after the call says it exists and only as far as its own header says it reaches.
    let sealed = !list.is_null()
        && unsafe { GetAce(list, 0, &raw mut first) } != 0
        && unsafe {
            let header = first.cast::<ACE_HEADER>();
            let entry = first.cast::<ACCESS_DENIED_ACE>();
            let sid_at = std::mem::offset_of!(ACCESS_DENIED_ACE, SidStart);
            u8::try_from(ACCESS_DENIED_ACE_TYPE).is_ok_and(|kind| (*header).AceType == kind)
                && usize::from((*header).AceSize) >= sid_at + OWNER_RIGHTS_SID.len()
                && (*entry).Mask & FILE_WRITE_ATTRIBUTES != 0
                && std::slice::from_raw_parts(
                    (&raw const (*entry).SidStart).cast::<u8>(),
                    OWNER_RIGHTS_SID.len(),
                ) == OWNER_RIGHTS_SID
        };
    // SAFETY: `descriptor` was allocated by the call above and is freed exactly once.
    unsafe {
        LocalFree(descriptor);
    }
    Ok(sealed)
}

/// Opens the one name `name` inside the directory `directory` is open on, never what a link there
/// leads to, with the given access and share mode.
///
/// The name is resolved against the handle by the system, in one step and without a path, which is
/// what `openat` is where it exists: nothing above the handle is consulted, so nothing that is
/// changed above it, or in the directory since the handle was opened, can send the open elsewhere.
/// A link is opened as itself, and a caller who needs to know checks the attributes of what it got.
///
/// # Errors
///
/// Returns the operating system's error, and [`io::ErrorKind::NotFound`] for a name whose removal
/// is already pending, which nothing can open and which is going.
fn open_inside(directory: &File, name: &[u16], access: u32, share: u32) -> io::Result<File> {
    // One component: a separator would leave the directory, and the whole-path forms the native
    // call reads would too.
    if name.is_empty()
        || name
            .iter()
            .any(|unit| *unit == 0 || *unit == u16::from(b'\\') || *unit == u16::from(b'/'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a name opened inside a directory is one component",
        ));
    }
    let length = u16::try_from(name.len() * 2)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "the name is too long"))?;
    let mut text = name.to_vec();
    let object_name = UNICODE_STRING {
        Length: length,
        MaximumLength: length,
        Buffer: text.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: u32::try_from(size_of::<OBJECT_ATTRIBUTES>()).unwrap_or(0),
        RootDirectory: directory.as_raw_handle(),
        ObjectName: &raw const object_name,
        Attributes: OBJ_DONT_REPARSE,
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut handle: HANDLE = std::ptr::null_mut();
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: `handle` and `status_block` are live out parameters; `attributes` points at
    // `object_name`, whose buffer is `text`, and all three live to the end of this function, past
    // the call. `directory` is a handle borrowed for the call, used as the root the name resolves
    // against. The options open an existing name only, so nothing is created. As `CreateFileW`
    // does, the access carries the right to wait on the handle and to read its attributes.
    let status = unsafe {
        NtOpenFile(
            &raw mut handle,
            access | SYNCHRONIZE | FILE_READ_ATTRIBUTES,
            &raw const attributes,
            &raw mut status_block,
            share,
            FILE_OPEN_REPARSE_POINT | FILE_OPEN_FOR_BACKUP_INTENT | FILE_SYNCHRONOUS_IO_NONALERT,
        )
    };
    if status == STATUS_SUCCESS {
        // SAFETY: the call above filled `handle` with a file handle this owns and closes once.
        return Ok(unsafe { File::from_raw_handle(handle) });
    }
    if status == STATUS_DELETE_PENDING {
        return Err(io::Error::from(io::ErrorKind::NotFound));
    }
    // SAFETY: the status is the one the call returned; this only maps it to a Win32 code.
    let code = unsafe { RtlNtStatusToDosError(status) };
    Err(io::Error::from_raw_os_error(code.cast_signed()))
}

/// Opens `path` itself, never what a link there leads to, with the given access and share mode.
fn open_name(path: &Path, access: u32, share: u32) -> io::Result<File> {
    OpenOptions::new()
        .access_mode(access)
        .share_mode(share)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
}

/// Deletes the name `reach` reaches through a handle opened for the purpose, so that a file other
/// names share is not changed in any way, and a name goes at once even while a program has the file
/// open with its delete shared.
fn delete_name(reach: Reach<'_>) -> io::Result<()> {
    mark_for_deletion(&reach.open(DELETE, SHARE_ALL)?)
}

/// Marks the object `file` is open on for deletion, with POSIX semantics and the system's rule for
/// a read-only file, so that its name goes when the handle closes and the rest of the name's file
/// is left as it was. The handle was opened with the right to delete.
fn mark_for_deletion(file: &File) -> io::Result<()> {
    let information = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE
            | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
            | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
    };
    // SAFETY: the handle is the open object's own, opened with the right to delete, and
    // `information` is the record the class asks for, with its size.
    let marked = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfoEx,
            (&raw const information).cast(),
            u32::try_from(size_of::<FILE_DISPOSITION_INFO_EX>()).unwrap_or(0),
        )
    };
    if marked == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The version of Windows this host runs, as the major and minor numbers the system states: `10.0`
/// for Windows 10 and 11. The system's own record is read, never a version a program compatibility
/// setting reports.
///
/// # Errors
///
/// Returns the operating system's error when it does not say.
pub fn windows_version() -> io::Result<(u32, u32)> {
    let mut information = OSVERSIONINFOW {
        dwOSVersionInfoSize: u32::try_from(size_of::<OSVERSIONINFOW>()).unwrap_or(0),
        ..OSVERSIONINFOW::default()
    };
    // SAFETY: `information` is a live buffer whose size field holds its size, as the call asks.
    let status = unsafe { RtlGetVersion(&raw mut information) };
    if status != 0 {
        return Err(io::Error::other(format!(
            "the system did not say its version: status {status:#x}"
        )));
    }
    Ok((information.dwMajorVersion, information.dwMinorVersion))
}

/// The bytes free for this account on the volume `path` is on.
///
/// # Errors
///
/// Returns the operating system's error when the volume cannot be asked.
pub fn free_space(path: &Path) -> io::Result<u64> {
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    let mut available = 0_u64;
    // SAFETY: `wide` is null-terminated and outlives the call, `available` is a live out
    // parameter, and the two totals are not asked for.
    let asked = unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &raw mut available,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if asked == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(available)
}
