//! The anchored walk: how the broker reaches an object under a directory it holds.
//!
//! Nothing here acts on a path string. A walk starts from a directory that is already open and has
//! been checked, lists its children with their identifiers, and opens each child by the name it
//! was listed under, relative to the held directory, without following a reparse point. An object
//! opened by its identifier cannot be deleted through and is not held against a rename, so the
//! name is how the handle is bound. Every such open asks for a right that takes part in share
//! checks (delete, or a data right) and gives no delete sharing, so while the handle is held the
//! object cannot be renamed or removed by anyone else; an open for attribute or security rights
//! alone holds nothing and is refused.
//!
//! Before a child is handed to its caller it is read back from the open handle: the whole key,
//! volume and identifier, is the one listed, the child's final path is the directory's own path
//! plus exactly one component, and its link count and attributes are known. A child that fails
//! any of these, or that cannot be read back at all, is a lost containment proof: the caller
//! changes nothing on it and reports it. Every directory from the start to the current one stays
//! open, without delete sharing, until the walk of its subtree ends, so no ancestor can be renamed
//! or removed while a descendant is acted on.
//!
//! A listing never reads more of a directory than the objects the walk still has left. A
//! directory opened by a recorded key ([`RecordedDir`]) compares the whole key on the handle it
//! returns and is never the anchor of a walk or a write: a recovery reopens the recorded chain by
//! name from the volume's root and compares each directory's identity instead.
//!
//! The volume's kind is checked once, on the first directory: NTFS on a local fixed volume only.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::mem::size_of;
use std::path::Path;
use std::ptr::null;

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_COMPLETE_IF_OPLOCKED, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_BY_FILE_ID,
    FILE_OPEN_FOR_BACKUP_INTENT, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
    FileFsDeviceInformation, NtCreateFile, NtQueryVolumeInformationFile,
};
use windows_sys::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_FILES, ERROR_PATH_NOT_FOUND, ERROR_SHARING_VIOLATION,
    GetLastError, HANDLE, RtlNtStatusToDosError, STATUS_OPLOCK_BREAK_IN_PROGRESS, UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
    FILE_ID_EXTD_DIR_INFO, FILE_ID_INFO, FILE_INFO_BY_HANDLE_CLASS, FILE_LIST_DIRECTORY,
    FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_STANDARD_INFO, FileAttributeTagInfo, FileIdExtdDirectoryInfo,
    FileIdExtdDirectoryRestartInfo, FileIdInfo, FileStandardInfo, GetFileInformationByHandleEx,
    GetFinalPathNameByHandleW, GetFullPathNameW, GetVolumeInformationByHandleW, VOLUME_NAME_NT,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

use super::ffi::{Handle, Result, error, last, wide_path};
use super::sd::OwnedSd;
use crate::filekey::FileKey;

/// The right to delete an object.
pub const DELETE: u32 = 0x0001_0000;
const READ_CONTROL: u32 = 0x0002_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;
const FILE_READ_DATA: u32 = 0x0001;
const FILE_WRITE_DATA: u32 = 0x0002;
const FILE_APPEND_DATA: u32 = 0x0004;
const FILE_EXECUTE: u32 = 0x0020;
/// The rights whose use is checked against what other handles to the same object allow. An open
/// with none of them (attributes, the descriptor, synchronise) conflicts with nothing and keeps
/// nothing from being renamed or deleted.
const HOLDING: u32 = DELETE | FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_EXECUTE;
const ERROR_INVALID_PARAMETER: u32 = 87;
const FILE_DEVICE_DISK: u32 = 7;
const FILE_REMOTE_DEVICE: u32 = 0x10;
const FILE_REMOVABLE_MEDIA: u32 = 0x01;

/// The access a directory needs to be listed and its descriptor read. Listing is a data right, so
/// a directory opened with it is held.
pub const LIST: u32 = FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE | FILE_LIST_DIRECTORY;

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
    /// The object opened, and the platform then refused to say what it is, with this error
    /// number.
    #[error("the object could not be read after it was opened (Windows error {0})")]
    Unreadable(u32),
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

/// What a bounded listing of a directory returned.
#[derive(Clone, Debug)]
pub struct Listing {
    /// The children, at most as many as the limit asked for.
    pub children: Vec<Child>,
    /// Whether the directory has more children than the limit.
    pub more: bool,
}

impl Listing {
    /// Whether the directory has no child at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.children.is_empty() && !self.more
    }
}

/// A child that was opened by its listed name and read back. Only [`DirHandle::open_child`] makes
/// one, so a handle that did not come from such an open cannot be turned into a held directory.
#[derive(Debug)]
pub struct Opened {
    handle: Handle,
    key: FileKey,
    kind: Kind,
    attributes: u32,
    links: u32,
}

impl Opened {
    /// The open handle. It is not open for delete sharing.
    #[must_use]
    pub fn handle(&self) -> &Handle {
        &self.handle
    }

    /// The object's identity.
    #[must_use]
    pub fn key(&self) -> FileKey {
        self.key
    }

    /// What kind of object it is.
    #[must_use]
    pub fn kind(&self) -> Kind {
        self.kind
    }

    /// The attributes read from the handle.
    #[must_use]
    pub fn attributes(&self) -> u32 {
        self.attributes
    }

    /// The number of names the object has.
    #[must_use]
    pub fn links(&self) -> u32 {
        self.links
    }

    /// Gives the handle up, for the removal to hand to the call that deletes through it.
    pub(super) fn into_handle(self) -> Handle {
        self.handle
    }
}

/// What the cases use to make the platform fail where a hostile tree cannot be made to, and to
/// count the platform calls a walk makes.
#[cfg(feature = "testing")]
pub mod testing {
    use std::sync::{Arc, Mutex};

    static FAIL_READ_OF: Mutex<Vec<String>> = Mutex::new(Vec::new());

    #[derive(Default)]
    struct Calls {
        opens: Vec<String>,
        listings: Vec<String>,
    }

    static RECORDINGS: Mutex<Vec<(String, Arc<Mutex<Calls>>)>> = Mutex::new(Vec::new());

    /// The opens of names and the listing calls made on directories whose final path holds a text,
    /// from [`record`] until it is dropped. A case records on the name of its own root, so cases
    /// that run side by side do not count each other's calls.
    pub struct Recording {
        calls: Arc<Mutex<Calls>>,
    }

    /// Starts recording the calls on directories whose final path holds `within`.
    #[must_use]
    pub fn record(within: &str) -> Recording {
        let calls = Arc::new(Mutex::new(Calls::default()));
        RECORDINGS
            .lock()
            .unwrap()
            .push((within.to_owned(), calls.clone()));
        Recording { calls }
    }

    impl Recording {
        /// Every open of a name made relative to a recorded directory, each as the directory's
        /// final path, a backslash and the name, in the order made. An open that fails counts.
        #[must_use]
        pub fn opens(&self) -> Vec<String> {
            self.calls.lock().unwrap().opens.clone()
        }

        /// How many times the platform was asked for entries of a recorded directory whose final
        /// path ends with `directory_ends_with`.
        #[must_use]
        pub fn listing_calls(&self, directory_ends_with: &str) -> usize {
            self.calls
                .lock()
                .unwrap()
                .listings
                .iter()
                .filter(|path| path.ends_with(directory_ends_with))
                .count()
        }
    }

    impl Drop for Recording {
        fn drop(&mut self) {
            RECORDINGS
                .lock()
                .unwrap()
                .retain(|(_, calls)| !Arc::ptr_eq(calls, &self.calls));
        }
    }

    pub(super) fn note_open(directory: &[u16], name: &[u16]) {
        let directory = String::from_utf16_lossy(directory);
        let name = String::from_utf16_lossy(name);
        for (within, calls) in RECORDINGS.lock().unwrap().iter() {
            if directory.contains(within.as_str()) {
                calls
                    .lock()
                    .unwrap()
                    .opens
                    .push(format!("{directory}\\{name}"));
            }
        }
    }

    pub(super) fn note_listing(directory: &[u16]) {
        let directory = String::from_utf16_lossy(directory);
        for (within, calls) in RECORDINGS.lock().unwrap().iter() {
            if directory.contains(within.as_str()) {
                calls.lock().unwrap().listings.push(directory.clone());
            }
        }
    }

    /// Makes the next read-back of the child listed under `name` fail, once, as if the platform
    /// had refused the query after the open.
    pub fn fail_next_read_of(name: &str) {
        FAIL_READ_OF.lock().unwrap().push(name.to_owned());
    }

    pub(super) fn take_failure(name: &str) -> bool {
        let mut names = FAIL_READ_OF.lock().unwrap();
        match names.iter().position(|wanted| wanted == name) {
            Some(index) => {
                names.remove(index);
                true
            }
            None => false,
        }
    }
}

/// A directory that is open, checked and held.
#[derive(Debug)]
pub struct DirHandle {
    handle: Handle,
    key: FileKey,
    path: Vec<u16>,
}

/// A directory that was opened by the key a journal row recorded, and whose whole key, volume and
/// identifier, was compared with the recorded one on the handle the open returned.
///
/// It gives the directory's key and its final path, which is what a recovery compares with the
/// chain it reopens by name. It is not a [`DirHandle`]: it lists nothing, opens nothing beneath
/// it and anchors no walk and no write, because an object that was opened by its identifier is
/// not held against a rename and cannot be deleted through.
#[derive(Debug)]
pub struct RecordedDir {
    _handle: Handle,
    key: FileKey,
    path: Vec<u16>,
}

impl RecordedDir {
    /// Opens a directory by the key a journal row recorded, from any open object on the same
    /// volume.
    ///
    /// # Errors
    ///
    /// Returns an error when the platform refuses a step. The inner error says why the object is
    /// not accepted: another key than the recorded one, a volume that is not accepted, a reparse
    /// point or something that is not a directory.
    pub fn open(
        hint: &Handle,
        key: &FileKey,
    ) -> Result<std::result::Result<RecordedDir, AnchorRefusal>> {
        let handle = open_by_key(hint, key, LIST, FILE_SHARE_READ | FILE_SHARE_WRITE)?;
        match checked_directory(handle)? {
            Err(refusal) => Ok(Err(refusal)),
            Ok(checked) if checked.key != *key => Ok(Err(AnchorRefusal::OtherObject)),
            Ok(checked) => Ok(Ok(RecordedDir {
                _handle: checked.handle,
                key: checked.key,
                path: checked.path,
            })),
        }
    }

    /// The directory's key, which equals the recorded one.
    #[must_use]
    pub fn key(&self) -> FileKey {
        self.key
    }

    /// The directory's final path when it was opened.
    #[must_use]
    pub fn path(&self) -> &[u16] {
        &self.path
    }
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

/// Refuses an open that asks for no right that takes part in share checks.
fn require_holding(access: u32) -> Result<()> {
    if access & HOLDING == 0 {
        return Err(error(
            ERROR_INVALID_PARAMETER,
            "an open that asks for no delete or data right holds nothing",
        ));
    }
    Ok(())
}

/// Whether `path` is `directory`'s path plus one backslash and exactly `name`.
fn is_beneath(directory: &[u16], path: &[u16], name: &[u16]) -> bool {
    path.len() == directory.len() + 1 + name.len()
        && path.starts_with(directory)
        && path[directory.len()] == u16::from(b'\\')
        && path[directory.len() + 1..] == *name
}

/// Opens an object on the volume of `hint` by its identifier, without following a reparse point.
/// The handle is not held against a rename and cannot be deleted through; the caller compares the
/// whole key on it. Like every open of an existing object it completes at once where a lock break
/// is owed, and then reports a sharing violation.
fn open_by_key(hint: &Handle, key: &FileKey, access: u32, share: u32) -> Result<Handle> {
    // The identifier is the name of the open: 16 bytes, as 8 units.
    let units: Vec<u16> = key
        .file_id
        .chunks_exact(2)
        .map(|pair| u16::from_ne_bytes([pair[0], pair[1]]))
        .collect();
    nt_create(
        hint.raw(),
        &units,
        access,
        share,
        FILE_OPEN,
        FILE_OPEN_BY_FILE_ID,
        None,
    )
}

/// An absolute path as the NT name that opens it, which is the one form a call that is not
/// `CreateFileW` takes. A path on another computer has none: the answer is `None`, and the anchor
/// is refused as a remote volume.
fn nt_path(path: &Path) -> Result<Option<Vec<u16>>> {
    let wide = wide_path(path);
    let mut full = vec![0_u16; 512];
    loop {
        // SAFETY: the path is NUL-terminated and the buffer length is passed.
        let length = unsafe {
            GetFullPathNameW(
                wide.as_ptr(),
                full.len() as u32,
                full.as_mut_ptr(),
                std::ptr::null_mut(),
            )
        };
        if length == 0 {
            return Err(last("making a path absolute"));
        }
        if (length as usize) < full.len() {
            full.truncate(length as usize);
            break;
        }
        full.resize(length as usize + 1, 0);
    }
    let slash = u16::from(b'\\');
    let question = u16::from(b'?');
    if full.len() > 4
        && full[0] == slash
        && full[1] == slash
        && full[2] == question
        && full[3] == slash
    {
        // `\\?\C:\x` is `\??\C:\x` in the NT space; the one that names a share,
        // `\\?\UNC\server\share`, is a path on another computer. Other `\\?\` forms
        // (`\\?\GLOBALROOT\Device\...`, `\\?\pipe\...`) reach the open, and `check_volume` refuses
        // what is not a local NTFS directory; anchors come from the administrator's configuration.
        // A `\\.\` path is not taken as an NT form: it falls to the refusal below with the other
        // paths that begin with two backslashes.
        let rest = String::from_utf16_lossy(&full[4..]).to_ascii_uppercase();
        if rest.starts_with("UNC\\") {
            return Ok(None);
        }
        full[1] = question;
        full[2] = question;
        return Ok(Some(full));
    }
    if full.len() > 2 && full[0] == slash && full[1] == slash {
        return Ok(None);
    }
    let mut nt = vec![slash, question, question, slash];
    nt.extend(full);
    Ok(Some(nt))
}

/// Checks an open directory the way every anchor and every recorded directory is checked: the
/// volume first (a remote file system does not answer the attribute query that follows), then that
/// the object is a directory and not a reparse point. Gives the handle back with its whole key and
/// its final path.
fn checked_directory(handle: Handle) -> Result<std::result::Result<Checked, AnchorRefusal>> {
    if let Err(refusal) = check_volume(&handle)? {
        return Ok(Err(AnchorRefusal::Volume(refusal)));
    }
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
    let key = key_of(&handle)?;
    let path = final_path(&handle)?;
    Ok(Ok(Checked { handle, key, path }))
}

/// A directory that passed [`checked_directory`].
struct Checked {
    handle: Handle,
    key: FileKey,
    path: Vec<u16>,
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
        DirHandle::open_anchor_with(path, LIST)
    }

    /// As [`DirHandle::open_anchor`], with the access the caller needs: it must include a data
    /// right, so that the held directory is not renamed or removed while it is used.
    ///
    /// # Errors
    ///
    /// Returns an error when `access` holds nothing or the platform refuses a step.
    pub fn open_anchor_with(
        path: &Path,
        access: u32,
    ) -> Result<std::result::Result<DirHandle, AnchorRefusal>> {
        require_holding(access)?;
        let Some(nt) = nt_path(path)? else {
            return Ok(Err(AnchorRefusal::Volume(VolumeRefusal::Remote)));
        };
        let handle = nt_create(
            std::ptr::null_mut(),
            &nt,
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            0,
            None,
        )?;
        DirHandle::checked(handle)
    }

    fn checked(handle: Handle) -> Result<std::result::Result<DirHandle, AnchorRefusal>> {
        Ok(checked_directory(handle)?.map(|checked| DirHandle {
            handle: checked.handle,
            key: checked.key,
            path: checked.path,
        }))
    }

    /// Gives the directory's handle up, for the removal to hand to the call that deletes through
    /// it.
    pub(super) fn into_handle(self) -> Handle {
        self.handle
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

    /// The children the directory lists now, with their identifiers, and not `.` or `..`, at most
    /// `limit` of them: the listing stops as soon as it holds `limit` and another child follows,
    /// so a directory with millions of entries is never read whole.
    ///
    /// # Errors
    ///
    /// Returns an error when the platform refuses the listing.
    pub fn children(&self, limit: usize) -> Result<Listing> {
        // 64 KiB, aligned for the records' 64-bit fields.
        let mut buffer = vec![0_u64; 8192];
        let mut class = FileIdExtdDirectoryRestartInfo;
        let mut children = Vec::new();
        loop {
            #[cfg(feature = "testing")]
            testing::note_listing(&self.path);
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
                    return Ok(Listing {
                        children,
                        more: false,
                    });
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
                    if children.len() == limit {
                        return Ok(Listing {
                            children,
                            more: true,
                        });
                    }
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

    /// Opens one listed child by its name, relative to this directory's handle, for the access given
    /// plus the right to read its attributes, checks that it is the object the listing named, and
    /// reads it back.
    ///
    /// The child is opened by name, and not by identifier, because the platform lets an object
    /// that was opened by identifier be renamed or deleted whatever the handle's sharing says, and
    /// holds one that was opened through its name. The handle is not open for delete sharing, so
    /// while it is held the child cannot be renamed or removed by anyone else. That holds only for
    /// an open that takes part in share checks, so `access` must include a delete or a data
    /// right: a call that asks for attribute or security rights alone is refused. The whole key,
    /// volume and identifier, is compared with the listing's on the handle returned. Its final path
    /// must be this directory's plus exactly the listed name, a file with several names included:
    /// only NTFS volumes are accepted, and on one a handle opened by name relative to a directory
    /// reports the name it was opened through. The caller reads `links` to learn that the object has
    /// other names.
    ///
    /// # Errors
    ///
    /// Returns an error when `access` holds nothing. Every failure that concerns the child, an
    /// open the platform refuses and a read of the open handle that fails, is a [`Lost`].
    pub fn open_child(
        &self,
        child: &Child,
        access: u32,
    ) -> Result<std::result::Result<Opened, Lost>> {
        require_holding(access)?;
        let handle = match self.nt_open_name(&child.name, access, false, FILE_OPEN) {
            Ok(handle) => handle,
            Err(failure)
                if failure.code == ERROR_FILE_NOT_FOUND || failure.code == ERROR_PATH_NOT_FOUND =>
            {
                return Ok(Err(Lost::Gone));
            }
            Err(failure) => return Ok(Err(Lost::Refused(failure.code))),
        };
        Ok(self
            .read_child(handle, child)
            .unwrap_or_else(|failure| Err(Lost::Unreadable(failure.code))))
    }

    /// Reads back an opened child: that it is the listed object, what kind it is, how many names it
    /// has, and that its place is this directory's plus the listed name.
    fn read_child(
        &self,
        handle: Handle,
        child: &Child,
    ) -> Result<std::result::Result<Opened, Lost>> {
        #[cfg(feature = "testing")]
        if testing::take_failure(&child.display()) {
            return Err(error(
                windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED,
                "a failure a case asked for",
            ));
        }
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
        let path = final_path(&handle)?;
        if !is_beneath(&self.path, &path, &child.name) {
            return Ok(Err(Lost::MovedOut));
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
        if opened.kind != Kind::Directory {
            return Err(error(
                ERROR_INVALID_PARAMETER,
                "only an object that read back as a directory is held as one",
            ));
        }
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
    /// The open returned an object whose key, volume or identifier, is not the recorded one.
    #[error("the object is not the one the key names")]
    OtherObject,
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
/// a child that fails that is listed in the report and nothing is done to it. A directory is
/// listed only as far as the objects the walk has left allow.
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
    let mut listed = 0;
    walk_directory(start, 1, bounds, &mut listed, visit, &mut report)?;
    Ok(report)
}

fn walk_directory(
    dir: &DirHandle,
    depth: usize,
    bounds: Bounds,
    listed: &mut usize,
    visit: &mut dyn FnMut(&Entry<'_>) -> Result<Verdict>,
    report: &mut Report,
) -> std::result::Result<(), WalkError> {
    let listing = dir.children(bounds.objects.saturating_sub(*listed))?;
    *listed += listing.children.len();
    for child in &listing.children {
        report.visited += 1;
        let verdict = visit(&Entry { dir, child, depth })?;
        let may_enter = child.attributes & FILE_ATTRIBUTE_DIRECTORY != 0
            && child.attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0;
        if verdict == Verdict::Skip || !may_enter {
            continue;
        }
        if depth >= bounds.depth {
            return Err(WalkError::TooDeep(bounds.depth));
        }
        match dir.open_child(child, LIST)? {
            Ok(opened) if opened.kind == Kind::Directory => match DirHandle::from_opened(opened) {
                Ok(held) => {
                    walk_directory(&held, depth + 1, bounds, listed, visit, report)?;
                }
                Err(failure) => report.problems.push(Problem {
                    name: child.display(),
                    lost: Lost::Unreadable(failure.code),
                }),
            },
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
    if listing.more {
        return Err(WalkError::TooLarge(bounds.objects));
    }
    Ok(())
}

/// The platform's own wording for a failed native call.
fn nt_error(status: i32, what: &str) -> super::ffi::Error {
    // SAFETY: converts a status code to a Windows error number; it reads nothing else.
    error(unsafe { RtlNtStatusToDosError(status) }, what)
}

impl DirHandle {
    /// Opens the name `name` directly beneath this directory for attributes alone, with every
    /// sharing, so that the object stays open and in nobody's way, and gives the handle to the
    /// removal's disposition check, which needs a second, independent open of its scratch file.
    ///
    /// # Errors
    ///
    /// Returns the platform's error when the name cannot be opened.
    pub(super) fn open_probe(&self, name: &[u16]) -> Result<Handle> {
        self.nt_open(name, 0, true, FILE_OPEN, 0, None)
    }

    /// Tells whether the name `name` exists directly beneath this directory. It is a probe and
    /// gives nothing else: the open is relative to this directory's handle, asks for no right but
    /// to read attributes, shares everything and is closed at once, so it holds nothing and
    /// follows no reparse point. An object a walk acts on is opened with [`DirHandle::open_child`].
    ///
    /// # Errors
    ///
    /// Returns the platform's error when the platform refuses the probe for a reason other than
    /// the name's absence.
    pub fn name_exists(&self, name: &[u16]) -> Result<bool> {
        match self.nt_open(name, 0, true, FILE_OPEN, 0, None) {
            Ok(_) => Ok(true),
            Err(failure)
                if failure.code == ERROR_FILE_NOT_FOUND || failure.code == ERROR_PATH_NOT_FOUND =>
            {
                Ok(false)
            }
            Err(failure) => Err(failure),
        }
    }

    /// Makes a new file named `name` directly beneath this directory, relative to its handle, and
    /// fails when the name exists.
    ///
    /// # Errors
    ///
    /// Returns the platform's error when the file cannot be made.
    pub fn create_file_named(&self, name: &[u16], access: u32) -> Result<Handle> {
        self.nt_open(name, access, false, FILE_CREATE, 0, None)
    }

    fn nt_open_name(
        &self,
        name: &[u16],
        access: u32,
        share_delete: bool,
        disposition: u32,
    ) -> Result<Handle> {
        self.nt_open(name, access, share_delete, disposition, 0, None)
    }

    fn nt_open(
        &self,
        name: &[u16],
        access: u32,
        share_delete: bool,
        disposition: u32,
        options: u32,
        descriptor: Option<&OwnedSd>,
    ) -> Result<Handle> {
        #[cfg(feature = "testing")]
        testing::note_open(&self.path, name);
        let share =
            FILE_SHARE_READ | FILE_SHARE_WRITE | if share_delete { FILE_SHARE_DELETE } else { 0 };
        nt_create(
            self.handle.raw(),
            name,
            access,
            share,
            disposition,
            options,
            descriptor,
        )
    }
}

/// Makes or opens the object `name` names, relative to the directory `root` (or an NT path when
/// `root` is null), with one call that never follows a reparse point.
///
/// A lock that another process holds on an existing object is broken by an open, and a synchronous
/// open waits inside the call for the holder to acknowledge, where no limit of the caller counts.
/// An open of an existing object asks to complete at once instead, and an answer that a break is
/// in progress is an object in use: the handle is closed and the error is a sharing violation.
fn nt_create(
    root: HANDLE,
    name: &[u16],
    access: u32,
    share: u32,
    disposition: u32,
    options: u32,
    descriptor: Option<&OwnedSd>,
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
        RootDirectory: root,
        ObjectName: &raw const text,
        // The flag that makes a lookup ignore case is not set, but the lookup in a directory that
        // does not tell names apart by case still matches a name that differs only by case. Names
        // come from a listing, so the open may reach another object with such a name; the
        // identity compared on the handle is what catches it.
        Attributes: 0,
        SecurityDescriptor: descriptor.map_or(null(), |sd| sd.as_ptr().cast_const().cast()),
        SecurityQualityOfService: null(),
    };
    let mut raw: HANDLE = std::ptr::null_mut();
    let mut status_block = IO_STATUS_BLOCK::default();
    let complete_if_oplocked = if disposition == FILE_OPEN {
        FILE_COMPLETE_IF_OPLOCKED
    } else {
        0
    };
    let file_attributes = if options & FILE_DIRECTORY_FILE != 0 {
        FILE_ATTRIBUTE_DIRECTORY
    } else {
        0
    };
    // SAFETY: the name, the attributes, the descriptor and the status block live through the
    // call, the directory handle (when there is one) is open, and the call keeps none of them.
    let status = unsafe {
        NtCreateFile(
            &raw mut raw,
            access | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            &raw const attributes,
            &raw mut status_block,
            null(),
            file_attributes,
            share,
            disposition,
            options
                | FILE_OPEN_REPARSE_POINT
                | FILE_OPEN_FOR_BACKUP_INTENT
                | FILE_SYNCHRONOUS_IO_NONALERT
                | complete_if_oplocked,
            null(),
            0,
        )
    };
    if status < 0 {
        return Err(nt_error(status, "opening an object"));
    }
    let handle = Handle::new(raw, "opening an object")?;
    if status == STATUS_OPLOCK_BREAK_IN_PROGRESS {
        // Another process holds an opportunistic lock on the object and has been asked to give it
        // up. The open did not wait for it to answer, so no limit on a wait is lost inside the
        // call; the object is in use, and the caller's bounded retries apply.
        drop(handle);
        return Err(error(
            ERROR_SHARING_VIOLATION,
            "the object is held by a lock that is being broken",
        ));
    }
    Ok(handle)
}

impl DirHandle {
    /// Opens the directory named `name` directly beneath this one, relative to its handle, and
    /// holds it: it must be a directory and not a reparse point, and its final path must be this
    /// directory's plus the name. `access` must include a delete or a data right, as for
    /// [`DirHandle::open_child`].
    ///
    /// # Errors
    ///
    /// Returns an error when `access` holds nothing or the platform refuses a call that is not a
    /// loss of the child.
    pub fn open_directory_named(
        &self,
        name: &[u16],
        access: u32,
    ) -> Result<std::result::Result<DirHandle, Lost>> {
        require_holding(access)?;
        let handle = match self.nt_open_name(name, access, false, FILE_OPEN) {
            Ok(handle) => handle,
            Err(failure)
                if failure.code == ERROR_FILE_NOT_FOUND || failure.code == ERROR_PATH_NOT_FOUND =>
            {
                return Ok(Err(Lost::Gone));
            }
            Err(failure) => return Ok(Err(Lost::Refused(failure.code))),
        };
        self.held_directory(handle, name)
    }

    /// Makes a new directory named `name` directly beneath this one with one create call,
    /// relative to this directory's handle, that carries `descriptor`: the directory has it from
    /// the first moment and inherits nothing from this one. The handle the call returns is the one
    /// held, so the object checked is the object made. The call fails when the name exists.
    /// `access` must include a delete or a data right, as for [`DirHandle::open_child`].
    ///
    /// # Errors
    ///
    /// Returns the platform's error when `access` holds nothing, the name exists or the directory
    /// cannot be made. The inner error says why what was made is not accepted.
    pub fn create_directory_named(
        &self,
        name: &[u16],
        descriptor: &OwnedSd,
        access: u32,
    ) -> Result<std::result::Result<DirHandle, Lost>> {
        require_holding(access)?;
        let handle = self.nt_open(
            name,
            access,
            false,
            FILE_CREATE,
            FILE_DIRECTORY_FILE,
            Some(descriptor),
        )?;
        self.held_directory(handle, name)
    }

    /// Checks an open handle to the directory `name` and turns it into a held directory.
    fn held_directory(
        &self,
        handle: Handle,
        name: &[u16],
    ) -> Result<std::result::Result<DirHandle, Lost>> {
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
        if !is_beneath(&self.path, &path, name) {
            return Ok(Err(Lost::MovedOut));
        }
        let key = key_of(&handle)?;
        Ok(Ok(DirHandle { handle, key, path }))
    }
}
