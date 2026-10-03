//! Files as the kernel identifies them on Windows, and the file a process was created from.
//!
//! A path names whatever is at it now. What a launch has to be held to is the file object that was
//! read, so every comparison here is of the volume and the 128-bit id the kernel gives an opened
//! file (`FILE_ID_INFO`), read from the handle and never from a name. A volume that gives no such
//! id (a FAT volume, a share) is refused by name: nothing there could be held to an identity.

#![expect(
    unsafe_code,
    reason = "asking the kernel about an opened file or a process is a call with out-parameters \
              that only the caller can promise"
)]

use std::os::windows::fs::OpenOptionsExt as _;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};

use windows_sys::Win32::Foundation::{ERROR_INVALID_PARAMETER, HANDLE};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_BASIC_INFO, FILE_ID_INFO, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FileBasicInfo, FileIdInfo, GetFileInformationByHandleEx,
};
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

/// `ProcessImageFileName`: the NT path of the file a process was created from.
const PROCESS_IMAGE_FILE_NAME: u32 = 27;

/// The status that asks for a larger buffer, as each of the three that mean it are spelled.
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004_u32.cast_signed();
const STATUS_BUFFER_TOO_SMALL: i32 = 0xC000_0023_u32.cast_signed();
const STATUS_BUFFER_OVERFLOW: i32 = 0x8000_0005_u32.cast_signed();

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryInformationProcess(
        process: HANDLE,
        class: u32,
        information: *mut std::ffi::c_void,
        length: u32,
        returned: *mut u32,
    ) -> i32;
}

/// One file object: the volume it is on and its id there, which no other object on that volume has
/// while it exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Object {
    /// The volume's serial number.
    pub volume: u64,
    /// The object's 128-bit id on that volume.
    pub id: u128,
}

/// When a file was last written and last changed, in nanoseconds on the system's own epoch.
///
/// The last access is not read: opening a file to hash it moves it, and an identity that moved
/// when it was read would never be the one that was hashed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Times {
    /// The last write.
    pub modified_ns: i128,
    /// The last change of any kind.
    pub changed_ns: i128,
}

/// Reads the object an opened file is.
///
/// # Errors
///
/// Returns why the volume gives no id for it, which refuses the file by name.
pub fn object_of(file: &std::fs::File) -> std::io::Result<Object> {
    // SAFETY: all zeroes is a structure of integers.
    let mut information: FILE_ID_INFO = unsafe { std::mem::zeroed() };
    // SAFETY: the handle is open for the call, and the structure is a local of the size told.
    let read = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle().cast(),
            FileIdInfo,
            std::ptr::from_mut(&mut information).cast(),
            u32::try_from(std::mem::size_of::<FILE_ID_INFO>()).unwrap_or(0),
        )
    };
    if read == 0 {
        return Err(std::io::Error::other(format!(
            "the volume gives this file no id, so it cannot be held to an identity: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(Object {
        volume: information.VolumeSerialNumber,
        id: u128::from_le_bytes(information.FileId.Identifier),
    })
}

/// Reads when an opened file was last written and last changed.
///
/// # Errors
///
/// Returns the operating system's failure.
pub fn times_of(file: &std::fs::File) -> std::io::Result<Times> {
    // SAFETY: all zeroes is a structure of integers.
    let mut information: FILE_BASIC_INFO = unsafe { std::mem::zeroed() };
    // SAFETY: as for the id: an open handle and a local of the size told.
    let read = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle().cast(),
            FileBasicInfo,
            std::ptr::from_mut(&mut information).cast(),
            u32::try_from(std::mem::size_of::<FILE_BASIC_INFO>()).unwrap_or(0),
        )
    };
    if read == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(Times {
        modified_ns: i128::from(information.LastWriteTime) * 100,
        changed_ns: i128::from(information.ChangeTime) * 100,
    })
}

/// Opens the file a process was created from, as the kernel recorded it, for its attributes only.
///
/// The kernel records the path as a device path (`\Device\HarddiskVolume1\...`) and keeps it as it
/// was when the process was created, so what this opens is whatever that path names now. It is
/// the object the process runs from only while nothing has moved the file since, which is what a
/// hold on the file guarantees and what the caller has to have taken before it asks.
///
/// # Errors
///
/// Returns why the process cannot be asked, or why its image cannot be opened.
pub fn image_of(pid: u32) -> Result<std::fs::File, String> {
    // SAFETY: the arguments are values; the call returns a handle this process owns, or null.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        let failure = std::io::Error::last_os_error();
        return Err(
            if failure
                .raw_os_error()
                .and_then(|code| u32::try_from(code).ok())
                == Some(ERROR_INVALID_PARAMETER)
            {
                format!("process {pid} is not there")
            } else {
                format!("process {pid} could not be opened: {failure}")
            },
        );
    }
    // SAFETY: the call reported a handle this process owns and nothing else holds.
    let process = unsafe { OwnedHandle::from_raw_handle(handle.cast()) };
    let mut capacity = 1024_usize;
    let name = loop {
        let mut buffer = vec![0_u8; capacity];
        let mut returned = 0_u32;
        // SAFETY: the handle is open for the call, and the buffer is a local of the length told.
        let status = unsafe {
            NtQueryInformationProcess(
                process.as_raw_handle().cast(),
                PROCESS_IMAGE_FILE_NAME,
                buffer.as_mut_ptr().cast(),
                u32::try_from(buffer.len()).unwrap_or(u32::MAX),
                &raw mut returned,
            )
        };
        if matches!(
            status,
            STATUS_INFO_LENGTH_MISMATCH | STATUS_BUFFER_TOO_SMALL | STATUS_BUFFER_OVERFLOW
        ) && capacity < 64 * 1024
        {
            capacity = usize::try_from(returned)
                .unwrap_or(capacity)
                .max(capacity * 2);
            continue;
        }
        if status < 0 {
            return Err(format!(
                "the kernel would not say which file process {pid} was created from (status \
                 {status:#x})"
            ));
        }
        break device_path_in(&buffer).ok_or_else(|| {
            format!("the kernel's record of process {pid}'s image is not a path")
        })?;
    };
    drop(process);
    open_device_path(&name)
}

/// Reads the path out of the `UNICODE_STRING` the kernel wrote at the start of a buffer, whose own
/// pointer points into that buffer.
fn device_path_in(buffer: &[u8]) -> Option<String> {
    let header = std::mem::size_of::<usize>() * 2;
    let length = usize::from(u16::from_le_bytes([*buffer.first()?, *buffer.get(1)?]));
    let start = header;
    let bytes = buffer.get(start..start.checked_add(length)?)?;
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    String::from_utf16(&units).ok()
}

/// Opens an NT device path for its attributes, with every share the file's holders may have.
fn open_device_path(name: &str) -> Result<std::fs::File, String> {
    let path = format!(r"\\?\GLOBALROOT{name}");
    std::fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .open(&path)
        .map_err(|error| format!("{name} cannot be opened: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The header of a `UNICODE_STRING` on a 64-bit machine is a length, a capacity and a pointer
    /// to the characters, which follow it in the same buffer.
    fn buffer_of(name: &str) -> Vec<u8> {
        let units: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut buffer = vec![0_u8; std::mem::size_of::<usize>() * 2];
        buffer[0..2].copy_from_slice(&u16::try_from(units.len()).expect("short").to_le_bytes());
        buffer.extend(units);
        buffer
    }

    #[test]
    fn the_path_is_read_from_after_the_string_s_header() {
        let buffer = buffer_of(r"\Device\HarddiskVolume3\a b\prog.exe");
        assert_eq!(
            device_path_in(&buffer).as_deref(),
            Some(r"\Device\HarddiskVolume3\a b\prog.exe")
        );
        assert_eq!(device_path_in(&[1, 0]), None, "a header that is not there");
        let mut truncated = buffer_of(r"\Device\x");
        truncated.truncate(truncated.len() - 2);
        assert_eq!(device_path_in(&truncated), None, "a string cut short");
    }
}
