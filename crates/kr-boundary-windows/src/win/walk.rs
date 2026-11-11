//! The anchored walk: how the broker reaches an object under a directory it holds.
//!
//! Nothing here acts on a path string. A walk starts from a directory that is already open and has
//! been checked, lists its children with their identifiers, and opens each child by that identifier
//! from the held directory, without following a reparse point. Before it hands a child to its
//! caller it reads the child back from the open handle: the identifier is the one listed, the
//! child's final path is the directory's own path plus exactly one component, and its link count
//! and attributes are known. A child that fails any of these is a lost containment proof: the
//! caller changes nothing on it and reports it. Every directory from the start to the current one
//! stays open, without delete sharing, until the walk of its subtree ends, so no ancestor can be
//! renamed or removed while a descendant is acted on.
//!
//! The volume's kind is checked once, on the first directory: NTFS on a local fixed volume only.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::mem::size_of;
use std::path::Path;
use std::ptr::null;

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_OPEN, FILE_OPEN_FOR_BACKUP_INTENT, FILE_OPEN_REPARSE_POINT,
    FILE_SYNCHRONOUS_IO_NONALERT, FileFsDeviceInformation, NtCreateFile,
    NtQueryVolumeInformationFile,
};
use windows_sys::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_FILES, ERROR_PATH_NOT_FOUND, GetLastError, HANDLE,
    RtlNtStatusToDosError, UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ExtendedFileIdType, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_128,
    FILE_ID_DESCRIPTOR, FILE_ID_DESCRIPTOR_0, FILE_ID_EXTD_DIR_INFO, FILE_ID_INFO,
    FILE_INFO_BY_HANDLE_CLASS, FILE_LIST_DIRECTORY, FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STANDARD_INFO, FileAttributeTagInfo,
    FileIdExtdDirectoryInfo, FileIdExtdDirectoryRestartInfo, FileIdInfo, FileStandardInfo,
    GetFileInformationByHandleEx, GetFinalPathNameByHandleW, GetVolumeInformationByHandleW,
    OPEN_EXISTING, OpenFileById, VOLUME_NAME_NT,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

use super::ffi::{Handle, Result, error, last, wide_path};
use crate::filekey::FileKey;

const READ_CONTROL: u32 = 0x0002_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;
const FILE_DEVICE_DISK: u32 = 7;
const FILE_REMOTE_DEVICE: u32 = 0x10;
const FILE_REMOVABLE_MEDIA: u32 = 0x01;

/// The access every object of a walk is opened with at the least: its attributes and identity.
pub const INSPECT: u32 = FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;
/// The access a directory needs to be listed.
pub const LIST: u32 = INSPECT | FILE_LIST_DIRECTORY;

/// How far a walk goes before it refuses a tree as too large.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bounds {
    /// The most objects a walk visits.
    pub objects: usize,
    /// The deepest directory level below the start.
    pub depth: usize,
}

/// The bounds of the private root's removal and of every other walk until a part sets its own.
pub const ROOT_BOUNDS: Bounds = Bounds {
    objects: 100_000,
    depth: 64,
};

/// Why a volume is not accepted, in words for the person.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum VolumeRefusal {
    /// The file system is not NTFS.
    #[error("the volume uses {0}, and only NTFS volumes are supported")]
    NotNtfs(String),
    /// The volume is on another computer.
    #[error("the volume is on another computer, and only local volumes are supported")]
    Remote,
    /// The volume is on removable media.
    #[error("the volume is on removable media, and only fixed volumes are supported")]
    Removable,
    /// The device is not an ordinary disk.
    #[error("the volume is not on an ordinary disk (device type {0})")]
    NotADisk(u32),
}

/// Checks that the object behind the handle is on an NTFS volume that is local and fixed, and
/// gives the volume's serial number.
///
/// # Errors
///
/// Returns an error when the platform cannot say what the volume is; an unreadable answer refuses.
pub fn check_volume(handle: &Handle) -> Result<std::result::Result<u64, VolumeRefusal>> {
    let mut serial = 0_u32;
    let mut name = [0_u16; 64];
    // SAFETY: the handle is open; every out-parameter is local and the name buffer length is given.
    let read = unsafe {
        GetVolumeInformationByHandleW(
            handle.raw(),
            std::ptr::null_mut(),
            0,
            &raw mut serial,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            name.as_mut_ptr(),
            name.len() as u32,
        )
    };
    if read == 0 {
        return Err(last("reading the volume's file system"));
    }
    let length = name
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(name.len());
    let file_system = String::from_utf16_lossy(&name[..length]);
    if file_system != "NTFS" {
        return Ok(Err(VolumeRefusal::NotNtfs(file_system)));
    }
    #[repr(C)]
    struct DeviceInformation {
        device_type: u32,
        characteristics: u32,
    }
    let mut device = DeviceInformation {
        device_type: 0,
        characteristics: 0,
    };
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: the handle is open and the buffer is the size of the structure the class returns.
    let status = unsafe {
        NtQueryVolumeInformationFile(
            handle.raw(),
            &raw mut status_block,
            (&raw mut device).cast::<c_void>(),
            size_of::<DeviceInformation>() as u32,
            FileFsDeviceInformation,
        )
    };
    if status < 0 {
        // SAFETY: converts a status code to a Windows error number; it reads nothing else.
        let code = unsafe { RtlNtStatusToDosError(status) };
        return Err(error(code, "reading the volume's device"));
    }
    if device.characteristics & FILE_REMOTE_DEVICE != 0 {
        return Ok(Err(VolumeRefusal::Remote));
    }
    if device.characteristics & FILE_REMOVABLE_MEDIA != 0 {
        return Ok(Err(VolumeRefusal::Removable));
    }
    if device.device_type != FILE_DEVICE_DISK {
        return Ok(Err(VolumeRefusal::NotADisk(device.device_type)));
    }
    Ok(Ok(volume_serial_of(handle)?))
}

/// The volume serial number the identifier calls carry, which is 64 bits wide.
fn volume_serial_of(handle: &Handle) -> Result<u64> {
    let info: FILE_ID_INFO = query(handle, FileIdInfo, "reading the volume's serial number")?;
    Ok(info.VolumeSerialNumber)
}

/// Why a child could not be shown to be where the listing said it was.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Lost {
    /// The listing named an object that is no longer there.
    #[error("the object is gone")]
    Gone,
    /// The identifier now names another object, or one on another volume.
    #[error("the identifier names another object")]
    IdentityChanged,
    /// The object is no longer directly beneath its directory.
    #[error("the object is no longer directly beneath its directory")]
    MovedOut,
    /// The platform refused the open, with this error number.
    #[error("the object could not be opened (Windows error {0})")]
    Refused(u32),
}

/// What kind of object a child is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A file.
    File,
    /// A directory that is not a reparse point.
    Directory,
    /// A reparse point of any kind, a directory junction and a symbolic link among them. It is
    /// never entered or followed.
    ReparsePoint,
}

/// One child as a directory's listing names it.
#[derive(Clone, Debug)]
pub struct Child {
    /// The name as stored, in UTF-16 units.
    pub name: Vec<u16>,
    /// The identifier the listing gave.
    pub key: FileKey,
    /// The attributes the listing gave.
    pub attributes: u32,
}

impl Child {
    /// The name for a message.
    #[must_use]
    pub fn display(&self) -> String {
        String::from_utf16_lossy(&self.name)
    }
}

/// A child that was opened by its identifier and read back.
#[derive(Debug)]
pub struct Opened {
    /// The open handle. It is not open for delete sharing.
    pub handle: Handle,
    /// The object's identity.
    pub key: FileKey,
    /// What kind of object it is.
    pub kind: Kind,
    /// The attributes read from the handle.
    pub attributes: u32,
    /// The number of names the object has.
    pub links: u32,
}

/// A directory that is open, checked and held.
#[derive(Debug)]
pub struct DirHandle {
    handle: Handle,
    key: FileKey,
    path: Vec<u16>,
}

/// A step of a walk that failed.
#[derive(Debug, thiserror::Error)]
pub enum WalkError {
    /// The platform refused a call.
    #[error("{0}")]
    Os(#[from] super::ffi::Error),
    /// The tree has more objects than a walk may visit.
    #[error("the tree has more than {0} objects")]
    TooLarge(usize),
    /// The tree is nested deeper than a walk may go.
    #[error("the tree is nested more than {0} levels deep")]
    TooDeep(usize),
}

/// A child the walk could not show to be where it was listed.
#[derive(Debug)]
pub struct Problem {
    /// The child's name.
    pub name: String,
    /// Why.
    pub lost: Lost,
}

/// What a walk saw.
#[derive(Debug, Default)]
pub struct Report {
    /// How many children were passed to the visitor or descended into.
    pub visited: usize,
    /// The children whose place could not be shown. Nothing was done to them.
    pub problems: Vec<Problem>,
}

/// What the visitor wants done with a directory it was shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Go into the directory.
    Descend,
    /// Do not go into the directory.
    Skip,
}

fn query<T: Default>(handle: &Handle, class: FILE_INFO_BY_HANDLE_CLASS, what: &str) -> Result<T> {
    let mut value = T::default();
    // SAFETY: the handle is open and the buffer is the structure the class fills, of the size given.
    let read = unsafe {
        GetFileInformationByHandleEx(
            handle.raw(),
            class,
            (&raw mut value).cast::<c_void>(),
            size_of::<T>() as u32,
        )
    };
    if read == 0 {
        return Err(last(what));
    }
    Ok(value)
}

fn key_of(handle: &Handle) -> Result<FileKey> {
    let info: FILE_ID_INFO = query(handle, FileIdInfo, "reading an object's identity")?;
    Ok(FileKey {
        volume_serial: info.VolumeSerialNumber,
        file_id: info.FileId.Identifier,
    })
}

/// The object's final path in the system's own form, as UTF-16 units.
fn final_path(handle: &Handle) -> Result<Vec<u16>> {
    let mut buffer = vec![0_u16; 512];
    loop {
        // SAFETY: the handle is open and the buffer length is passed.
        let length = unsafe {
            GetFinalPathNameByHandleW(
                handle.raw(),
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                FILE_NAME_NORMALIZED | VOLUME_NAME_NT,
            )
        };
        if length == 0 {
            return Err(last("reading an object's final path"));
        }
        if (length as usize) < buffer.len() {
            buffer.truncate(length as usize);
            return Ok(buffer);
        }
        buffer.resize(length as usize + 1, 0);
    }
}

/// Opens an object on the volume of `hint` by its identifier, without following a reparse point.
fn open_by_key(hint: &Handle, key: &FileKey, access: u32, share: u32) -> Result<Handle> {
    let descriptor = FILE_ID_DESCRIPTOR {
        dwSize: size_of::<FILE_ID_DESCRIPTOR>() as u32,
        Type: ExtendedFileIdType,
        Anonymous: FILE_ID_DESCRIPTOR_0 {
            ExtendedFileId: FILE_ID_128 {
                Identifier: key.file_id,
            },
        },
    };
    // SAFETY: the hint is open on the volume, the descriptor is complete and the call keeps neither.
    let raw = unsafe {
        OpenFileById(
            hint.raw(),
            &raw const descriptor,
            access,
            share,
            null(),
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        )
    };
    Handle::new(raw as HANDLE, "opening an object by its identifier")
}

impl DirHandle {
    /// Opens the anchor of a walk by its path: the one place a path is used. The anchor is a
    /// directory that only administrators can change. It must be a directory, not a reparse point,
    /// and on a volume that [`check_volume`] accepts.
    ///
    /// # Errors
    ///
    /// Returns an error when the platform refuses a step. The inner error says why the anchor is
    /// not accepted when it is a volume or an object of the wrong kind.
    pub fn open_anchor(path: &Path) -> Result<std::result::Result<DirHandle, AnchorRefusal>> {
        let wide = wide_path(path);
        // SAFETY: the path is NUL-terminated; the call keeps nothing of it.
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                LIST,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        let handle = Handle::new(raw, "opening the directory a walk starts from")?;
        DirHandle::checked(handle)
    }

    /// Opens a directory by the identifier a journal row recorded, from any open object on the
    /// same volume.
    ///
    /// # Errors
    ///
    /// Returns an error when the platform refuses a step.
    pub fn open_by_key(
        hint: &Handle,
        key: &FileKey,
    ) -> Result<std::result::Result<DirHandle, AnchorRefusal>> {
        let handle = open_by_key(hint, key, LIST, FILE_SHARE_READ | FILE_SHARE_WRITE)?;
        DirHandle::checked(handle)
    }

    fn checked(handle: Handle) -> Result<std::result::Result<DirHandle, AnchorRefusal>> {
        let tag: FILE_ATTRIBUTE_TAG_INFO = query(
            &handle,
            FileAttributeTagInfo,
            "reading the directory's attributes",
        )?;
        if tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Ok(Err(AnchorRefusal::ReparsePoint));
        }
        if tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
            return Ok(Err(AnchorRefusal::NotADirectory));
        }
        if let Err(refusal) = check_volume(&handle)? {
            return Ok(Err(AnchorRefusal::Volume(refusal)));
        }
        let key = key_of(&handle)?;
        let path = final_path(&handle)?;
        Ok(Ok(DirHandle { handle, key, path }))
    }

    /// The directory's identity.
    #[must_use]
    pub fn key(&self) -> FileKey {
        self.key
    }

    /// The directory's final path when it was opened, for a message and for the containment check.
    #[must_use]
    pub fn path(&self) -> &[u16] {
        &self.path
    }

    /// The open handle, for a call that takes the directory as its root.
    #[must_use]
    pub fn handle(&self) -> &Handle {
        &self.handle
    }

    /// The children the directory lists now, with their identifiers, and not `.` or `..`.
    ///
    /// # Errors
    ///
    /// Returns an error when the platform refuses the listing.
    pub fn children(&self) -> Result<Vec<Child>> {
        // 64 KiB, aligned for the records' 64-bit fields.
        let mut buffer = vec![0_u64; 8192];
        let mut class = FileIdExtdDirectoryRestartInfo;
        let mut children = Vec::new();
        loop {
            // SAFETY: the handle is open for listing and the buffer length is passed.
            let read = unsafe {
                GetFileInformationByHandleEx(
                    self.handle.raw(),
                    class,
                    buffer.as_mut_ptr().cast::<c_void>(),
                    (buffer.len() * size_of::<u64>()) as u32,
                )
            };
            class = FileIdExtdDirectoryInfo;
            if read == 0 {
                // SAFETY: reads the calling thread's last error.
                let code = unsafe { GetLastError() };
                if code == ERROR_NO_MORE_FILES {
                    return Ok(children);
                }
                return Err(error(code, "listing a directory"));
            }
            let base = buffer.as_ptr().cast::<u8>();
            let mut offset = 0_usize;
            loop {
                // SAFETY: the platform filled records of this layout one after another, each
                // 8-byte aligned, and `offset` only moves by the length each record states.
                let record = unsafe { &*base.add(offset).cast::<FILE_ID_EXTD_DIR_INFO>() };
                let units = record.FileNameLength as usize / 2;
                // SAFETY: the name's units follow the fixed fields and lie inside the record.
                let name = unsafe {
                    std::slice::from_raw_parts(
                        std::ptr::addr_of!(record.FileName).cast::<u16>(),
                        units,
                    )
                };
                let dots = name == [u16::from(b'.')] || name == [u16::from(b'.'), u16::from(b'.')];
                if !dots {
                    children.push(Child {
                        name: name.to_vec(),
                        key: FileKey {
                            volume_serial: self.key.volume_serial,
                            file_id: record.FileId.Identifier,
                        },
                        attributes: record.FileAttributes,
                    });
                }
                if record.NextEntryOffset == 0 {
                    break;
                }
                offset += record.NextEntryOffset as usize;
            }
        }
    }

    /// Opens one listed child by its identifier, from this directory, for the access given plus
    /// the right to read its attributes, and reads it back.
    ///
    /// The handle is not open for delete sharing, so while it is held the child cannot be renamed
    /// or removed by anyone else. A directory, or a file with one name, must have a final path
    /// that is this directory's plus exactly the listed name. A file with more than one name may
    /// show any of them as its final path, so its place is not shown that way and the caller reads
    /// `links` and decides.
    ///
    /// # Errors
    ///
    /// Returns an error when the platform refuses a call that is not a loss of the child.
    pub fn open_child(
        &self,
        child: &Child,
        access: u32,
    ) -> Result<std::result::Result<Opened, Lost>> {
        let handle = match open_by_key(
            &self.handle,
            &child.key,
            access | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
        ) {
            Ok(handle) => handle,
            Err(failure)
                if failure.code == ERROR_FILE_NOT_FOUND || failure.code == ERROR_PATH_NOT_FOUND =>
            {
                return Ok(Err(Lost::Gone));
            }
            Err(failure) => return Ok(Err(Lost::Refused(failure.code))),
        };
        if key_of(&handle)? != child.key {
            return Ok(Err(Lost::IdentityChanged));
        }
        let tag: FILE_ATTRIBUTE_TAG_INFO = query(
            &handle,
            FileAttributeTagInfo,
            "reading an object's attributes",
        )?;
        let standard: FILE_STANDARD_INFO =
            query(&handle, FileStandardInfo, "reading an object's link count")?;
        let kind = if tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            Kind::ReparsePoint
        } else if standard.Directory {
            Kind::Directory
        } else {
            Kind::File
        };
        let several_names = kind == Kind::File && standard.NumberOfLinks > 1;
        if !several_names {
            let path = final_path(&handle)?;
            let beneath = path.len() == self.path.len() + 1 + child.name.len()
                && path.starts_with(&self.path)
                && path[self.path.len()] == u16::from(b'\\')
                && path[self.path.len() + 1..] == child.name[..];
            if !beneath {
                return Ok(Err(Lost::MovedOut));
            }
        }
        Ok(Ok(Opened {
            handle,
            key: child.key,
            kind,
            attributes: tag.FileAttributes,
            links: standard.NumberOfLinks,
        }))
    }

    /// Turns a directory that was opened as a child, with listing access, into a held directory.
    pub(super) fn from_opened(opened: Opened) -> Result<DirHandle> {
        let path = final_path(&opened.handle)?;
        Ok(DirHandle {
            handle: opened.handle,
            key: opened.key,
            path,
        })
    }
}

/// Why an anchor is not accepted.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AnchorRefusal {
    /// The object is a reparse point.
    #[error("the directory is a reparse point")]
    ReparsePoint,
    /// The object is not a directory.
    #[error("the object is not a directory")]
    NotADirectory,
    /// The volume is not accepted.
    #[error("{0}")]
    Volume(VolumeRefusal),
}

/// One child shown to the visitor, with the directory that holds it.
pub struct Entry<'a> {
    /// The held directory the child was listed from.
    pub dir: &'a DirHandle,
    /// The child as listed.
    pub child: &'a Child,
    /// The level below the start, one for the start's own children.
    pub depth: usize,
}

impl Entry<'_> {
    /// Opens the child with the access the action needs, from the held directory, and reads it
    /// back. See [`DirHandle::open_child`].
    ///
    /// # Errors
    ///
    /// Returns an error when the platform refuses a call that is not a loss of the child.
    pub fn open(&self, access: u32) -> Result<std::result::Result<Opened, Lost>> {
        self.dir.open_child(self.child, access)
    }
}

/// Walks the tree below `start`, calling `visit` for every child before it goes into it.
///
/// A directory is entered only when the visitor says so, only when it is a directory and not a
/// reparse point, and only when it opens and reads back as described at [`DirHandle::open_child`];
/// a child that fails that is listed in the report and nothing is done to it.
///
/// # Errors
///
/// Returns an error when the platform refuses a call, the tree is larger than `bounds` or the
/// visitor fails.
pub fn walk(
    start: &DirHandle,
    bounds: Bounds,
    visit: &mut dyn FnMut(&Entry<'_>) -> Result<Verdict>,
) -> std::result::Result<Report, WalkError> {
    let mut report = Report::default();
    walk_directory(start, 1, bounds, visit, &mut report)?;
    Ok(report)
}

fn walk_directory(
    dir: &DirHandle,
    depth: usize,
    bounds: Bounds,
    visit: &mut dyn FnMut(&Entry<'_>) -> Result<Verdict>,
    report: &mut Report,
) -> std::result::Result<(), WalkError> {
    for child in dir.children()? {
        report.visited += 1;
        if report.visited > bounds.objects {
            return Err(WalkError::TooLarge(bounds.objects));
        }
        let verdict = visit(&Entry {
            dir,
            child: &child,
            depth,
        })?;
        let may_enter = child.attributes & FILE_ATTRIBUTE_DIRECTORY != 0
            && child.attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0;
        if verdict == Verdict::Skip || !may_enter {
            continue;
        }
        if depth >= bounds.depth {
            return Err(WalkError::TooDeep(bounds.depth));
        }
        match dir.open_child(&child, LIST)? {
            Ok(opened) if opened.kind == Kind::Directory => {
                let held = DirHandle::from_opened(opened)?;
                walk_directory(&held, depth + 1, bounds, visit, report)?;
            }
            Ok(_) => report.problems.push(Problem {
                name: child.display(),
                lost: Lost::IdentityChanged,
            }),
            Err(lost) => report.problems.push(Problem {
                name: child.display(),
                lost,
            }),
        }
    }
    Ok(())
}

/// The platform's own wording for a failed native call.
fn nt_error(status: i32, what: &str) -> super::ffi::Error {
    // SAFETY: converts a status code to a Windows error number; it reads nothing else.
    error(unsafe { RtlNtStatusToDosError(status) }, what)
}

impl DirHandle {
    /// Opens the name `name` directly beneath this directory, relative to its handle and never
    /// through a path, without following a reparse point: a link is opened as itself. The handle
    /// is not open for delete sharing unless `share_delete` says so.
    ///
    /// # Errors
    ///
    /// Returns the platform's error when the name cannot be opened.
    pub fn open_name(&self, name: &[u16], access: u32, share_delete: bool) -> Result<Handle> {
        self.nt_open_name(name, access, share_delete, FILE_OPEN)
    }

    /// Makes a new file named `name` directly beneath this directory, relative to its handle, and
    /// fails when the name exists.
    ///
    /// # Errors
    ///
    /// Returns the platform's error when the file cannot be made.
    pub fn create_file_named(&self, name: &[u16], access: u32) -> Result<Handle> {
        self.nt_open_name(name, access, false, FILE_CREATE)
    }

    fn nt_open_name(
        &self,
        name: &[u16],
        access: u32,
        share_delete: bool,
        disposition: u32,
    ) -> Result<Handle> {
        let bytes = name.len() * 2;
        if bytes > usize::from(u16::MAX) {
            return Err(error(
                ERROR_FILE_NOT_FOUND,
                "a name too long for the platform",
            ));
        }
        let mut units = name.to_vec();
        let text = UNICODE_STRING {
            Length: bytes as u16,
            MaximumLength: bytes as u16,
            Buffer: units.as_mut_ptr(),
        };
        let attributes = OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: self.handle.raw(),
            ObjectName: &raw const text,
            // Names come from a listing and are matched exactly, so a directory that tells names apart
            // by case never opens the wrong one.
            Attributes: 0,
            SecurityDescriptor: null(),
            SecurityQualityOfService: null(),
        };
        let mut raw: HANDLE = std::ptr::null_mut();
        let mut status_block = IO_STATUS_BLOCK::default();
        let share =
            FILE_SHARE_READ | FILE_SHARE_WRITE | if share_delete { FILE_SHARE_DELETE } else { 0 };
        // SAFETY: the name, the attributes and the status block live through the call, the
        // directory handle is open, and the call keeps none of them.
        let status = unsafe {
            NtCreateFile(
                &raw mut raw,
                access | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                &raw const attributes,
                &raw mut status_block,
                null(),
                0,
                share,
                disposition,
                FILE_OPEN_REPARSE_POINT
                    | FILE_OPEN_FOR_BACKUP_INTENT
                    | FILE_SYNCHRONOUS_IO_NONALERT,
                null(),
                0,
            )
        };
        if status < 0 {
            return Err(nt_error(status, "opening a name beneath a held directory"));
        }
        Handle::new(raw, "opening a name beneath a held directory")
    }
}

impl DirHandle {
    /// Opens the directory named `name` directly beneath this one, relative to its handle, and
    /// holds it: it must be a directory and not a reparse point, and its final path must be this
    /// directory's plus the name.
    ///
    /// # Errors
    ///
    /// Returns an error when the platform refuses a call that is not a loss of the child.
    pub fn open_directory_named(
        &self,
        name: &[u16],
        access: u32,
    ) -> Result<std::result::Result<DirHandle, Lost>> {
        let handle = match self.open_name(name, access, false) {
            Ok(handle) => handle,
            Err(failure)
                if failure.code == ERROR_FILE_NOT_FOUND || failure.code == ERROR_PATH_NOT_FOUND =>
            {
                return Ok(Err(Lost::Gone));
            }
            Err(failure) => return Ok(Err(Lost::Refused(failure.code))),
        };
        let tag: FILE_ATTRIBUTE_TAG_INFO = query(
            &handle,
            FileAttributeTagInfo,
            "reading a directory's attributes",
        )?;
        if tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
        {
            return Ok(Err(Lost::IdentityChanged));
        }
        let path = final_path(&handle)?;
        let beneath = path.len() == self.path.len() + 1 + name.len()
            && path.starts_with(&self.path)
            && path[self.path.len()] == u16::from(b'\\')
            && path[self.path.len() + 1..] == *name;
        if !beneath {
            return Ok(Err(Lost::MovedOut));
        }
        let key = key_of(&handle)?;
        Ok(Ok(DirHandle { handle, key, path }))
    }
}
