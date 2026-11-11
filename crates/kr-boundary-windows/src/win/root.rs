//! An invocation's private root: its creation and its removal.
//!
//! The root is one directory under the broker's `run` directory, with a random name, made by a
//! single call that carries its descriptor, so that it never inherits an entry from the folder
//! above. Under it are `tmp` and `home`, made the same way. Git runs as a boundary account and
//! may fill the root with anything its group can write: links to outside names, junctions, long
//! and case-sensitive names, read-only files, files with open handles, objects whose own
//! permission list refuses the system. The removal is written for exactly that and writes no
//! permission list and no attribute on anything.
//!
//! The removal works from the bottom up, from handles, on the walk's primitives. A reparse point,
//! and a file with more than one name, is removed by its name, opened relative to its parent's
//! handle and never through its target, so a link's target and a hard link's other names stay as
//! they were. Every other object is opened by its identifier from the held directory, with the
//! right to delete it and the backup and restore privileges that the guard on this thread holds,
//! and is deleted with the platform's POSIX semantics, which ignore the read-only attribute. An
//! object that still cannot be opened, or stays in use for five seconds, is a leftover: its
//! reason and path are returned, and nothing on it is changed.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use windows_sys::Wdk::Storage::FileSystem::{
    FILE_DISPOSITION_DELETE, FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE,
    FILE_DISPOSITION_INFORMATION_EX, FILE_DISPOSITION_POSIX_SEMANTICS,
    FileDispositionInformationEx, NtSetInformationFile,
};
use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION};
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

use super::ffi::{Handle, Sid, error, last, wide_path};
use super::privilege::PrivGuard;
use super::sd::{self, Principals, SdKind};
use super::walk::{Bounds, Child, DirHandle, Kind, LIST, Lost, ROOT_BOUNDS};
use crate::filekey::FileKey;

const DELETE: u32 = 0x0001_0000;
const READ_CONTROL: u32 = 0x0002_0000;
/// How long the removal waits for an object that is in use before it calls it a leftover.
const IN_USE_WAIT: Duration = Duration::from_secs(5);
const RETRY_EVERY: Duration = Duration::from_millis(100);

/// The rows the root writes about itself, each durable before the step it protects.
pub trait RootRows {
    /// The root is about to be made at this path.
    ///
    /// # Errors
    ///
    /// Returns an error when the row is not durable; nothing is made then.
    fn intent(&mut self, path: &Path) -> Result<(), RootError>;
    /// The root was made, and this is its identity.
    ///
    /// # Errors
    ///
    /// Returns an error when the row cannot be written.
    fn made(&mut self, path: &Path, key: &FileKey) -> Result<(), RootError>;
    /// The root was removed.
    ///
    /// # Errors
    ///
    /// Returns an error when the row cannot be written.
    fn removed(&mut self) -> Result<(), RootError>;
}

/// A failure of the root's creation or removal.
#[derive(Debug, thiserror::Error)]
pub enum RootError {
    /// The platform refused a call.
    #[error("{0}")]
    Os(#[from] super::ffi::Error),
    /// A row could not be written.
    #[error("the journal could not take the row: {0}")]
    Journal(String),
    /// What was made is not what was asked for.
    #[error("{0}")]
    Refused(String),
}

/// An object the removal could not remove. Nothing on it was changed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leftover {
    /// Where it is, below the root, with the root's name left out.
    pub path: String,
    /// Why it stayed.
    pub reason: String,
}

impl std::fmt::Display for Leftover {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "leftover: {} {}", self.reason, self.path)
    }
}

/// A private root that was made and is held open.
#[derive(Debug)]
pub struct PrivateRoot {
    dir: DirHandle,
    path: PathBuf,
}

impl PrivateRoot {
    /// The root's path as the invocation's environment names it.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The root's `tmp` directory.
    #[must_use]
    pub fn tmp(&self) -> PathBuf {
        self.path.join("tmp")
    }

    /// The root's `home` directory.
    #[must_use]
    pub fn home(&self) -> PathBuf {
        self.path.join("home")
    }

    /// The root's identity, for the journal.
    #[must_use]
    pub fn key(&self) -> FileKey {
        self.dir.key()
    }

    /// The held directory, which stays open without delete sharing until the root is removed.
    #[must_use]
    pub fn dir(&self) -> &DirHandle {
        &self.dir
    }
}

fn random_name() -> Result<String, RootError> {
    let mut bytes = [0_u8; 16];
    // SAFETY: the buffer is 16 bytes, which is the length passed; no algorithm handle is used.
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 {
        return Err(error(status as u32, "drawing a random name for the private root").into());
    }
    Ok(hex::encode(bytes))
}

/// Makes a directory with one call that carries the descriptor. The call fails on an existing
/// name.
fn make_directory(path: &Path, descriptor: &sd::OwnedSd) -> Result<(), RootError> {
    let wide = wide_path(path);
    let attributes = descriptor.attributes();
    // SAFETY: the path is NUL-terminated and the attributes point at a descriptor that lives
    // through the call.
    if unsafe { CreateDirectoryW(wide.as_ptr(), &raw const attributes) } == 0 {
        return Err(last(format!("making the directory {}", path.display())).into());
    }
    Ok(())
}

/// Makes the private root for an invocation under `run`, the held directory at `run_path`.
///
/// The row `intent` is durable before the directory is made and `made` after it is made and
/// checked. The check opens the new directory relative to `run`, requires a directory that is not
/// a reparse point and directly beneath `run`, and reads its descriptor back and compares it with
/// the one sent.
///
/// A failure after the intent may leave the directory behind; the recovery of an intent without
/// its `made` row looks for it by its name and removes it.
///
/// # Errors
///
/// Returns an error when a row cannot be written, the platform refuses a call, or what was made
/// is not what was asked for.
pub fn create_root(
    run: &DirHandle,
    run_path: &Path,
    group: &Sid,
    rows: &mut dyn RootRows,
) -> Result<PrivateRoot, RootError> {
    let principals = Principals {
        group: Some(group.clone()),
        ..Principals::default()
    };
    let descriptor = sd::descriptor(SdKind::PrivateRoot, &principals)?;
    let name = random_name()?;
    let path = run_path.join(&name);
    rows.intent(&path)?;
    make_directory(&path, &descriptor)?;
    let wide_name: Vec<u16> = name.encode_utf16().collect();
    let held = run
        .open_directory_named(&wide_name, LIST | DELETE | READ_CONTROL)?
        .map_err(|lost| RootError::Refused(format!("the new private root: {lost}")))?;
    let wanted = descriptor.summary()?;
    let found = sd::summary_of_handle(held.handle())?;
    if found != wanted {
        return Err(RootError::Refused(
            "the private root's descriptor is not the one that was sent".to_owned(),
        ));
    }
    rows.made(&path, &held.key())?;
    for part in ["tmp", "home"] {
        make_directory(&path.join(part), &descriptor)?;
        let units: Vec<u16> = part.encode_utf16().collect();
        let inner = held
            .open_directory_named(&units, LIST | READ_CONTROL)?
            .map_err(|lost| RootError::Refused(format!("the root's {part} directory: {lost}")))?;
        if sd::summary_of_handle(inner.handle())?.owner != wanted.owner {
            return Err(RootError::Refused(format!(
                "the root's {part} directory has another owner than the root"
            )));
        }
    }
    Ok(PrivateRoot { dir: held, path })
}

/// Removes the private root and everything under it. The privileged thread's guard is the proof
/// that the call runs inside a walk.
///
/// Returns what could not be removed. When nothing is left over the root itself is gone and the
/// `removed` row is written; otherwise the root stays, and so does everything the removal could
/// not take.
///
/// # Errors
///
/// Returns an error when a row cannot be written or the platform refuses a call the removal
/// cannot work around.
pub fn remove_root(
    root: &PrivateRoot,
    guard: &PrivGuard,
    rows: &mut dyn RootRows,
) -> Result<Vec<Leftover>, RootError> {
    remove_root_within(root, guard, ROOT_BOUNDS, rows)
}

/// As [`remove_root`], with the bounds a case chooses.
///
/// # Errors
///
/// See [`remove_root`].
pub fn remove_root_within(
    root: &PrivateRoot,
    _guard: &PrivGuard,
    bounds: Bounds,
    rows: &mut dyn RootRows,
) -> Result<Vec<Leftover>, RootError> {
    let mut state = Removal {
        bounds,
        seen: 0,
        leftovers: Vec::new(),
    };
    state.empty(&root.dir, "", 1)?;
    if state.leftovers.is_empty() {
        match delete(root.dir.handle()) {
            Ok(()) => rows.removed()?,
            Err(failure) => state.leftovers.push(Leftover {
                path: String::new(),
                reason: format!("the root itself could not be removed ({})", failure.code),
            }),
        }
    }
    Ok(state.leftovers)
}

struct Removal {
    bounds: Bounds,
    seen: usize,
    leftovers: Vec<Leftover>,
}

impl Removal {
    fn leave(&mut self, path: &str, reason: impl Into<String>) {
        self.leftovers.push(Leftover {
            path: path.to_owned(),
            reason: reason.into(),
        });
    }

    /// Removes every child of `dir`, which is held open with the right to delete it.
    fn empty(&mut self, dir: &DirHandle, at: &str, depth: usize) -> Result<(), RootError> {
        for child in dir.children()? {
            self.seen += 1;
            let path = if at.is_empty() {
                child.display()
            } else {
                format!("{at}\\{}", child.display())
            };
            if self.seen > self.bounds.objects {
                self.leave(&path, "too large");
                continue;
            }
            self.remove_child(dir, &child, &path, depth)?;
        }
        Ok(())
    }

    fn remove_child(
        &mut self,
        dir: &DirHandle,
        child: &Child,
        path: &str,
        depth: usize,
    ) -> Result<(), RootError> {
        if child.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return self.remove_by_name(dir, child, path);
        }
        let is_directory = child.attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
        if is_directory && depth >= self.bounds.depth {
            self.leave(path, "too large");
            return Ok(());
        }
        let access = DELETE | if is_directory { LIST } else { 0 };
        let opened = match open_waiting(dir, child, access)? {
            Ok(opened) => opened,
            Err(Lost::Gone) => return Ok(()),
            Err(lost) => {
                self.leave(path, lost.to_string());
                return Ok(());
            }
        };
        match opened.kind {
            Kind::ReparsePoint => {
                drop(opened);
                self.remove_by_name(dir, child, path)
            }
            Kind::File if opened.links > 1 => {
                drop(opened);
                self.remove_by_name(dir, child, path)
            }
            Kind::File => {
                if let Err(failure) = delete(&opened.handle) {
                    self.leave(
                        path,
                        format!("not removed (Windows error {})", failure.code),
                    );
                }
                Ok(())
            }
            Kind::Directory => {
                let held = DirHandle::from_opened(opened)?;
                self.empty(&held, path, depth + 1)?;
                if !held.children()?.is_empty() {
                    self.leave(path, "not empty after its contents were removed");
                } else if let Err(failure) = delete(held.handle()) {
                    self.leave(
                        path,
                        format!("not removed (Windows error {})", failure.code),
                    );
                }
                Ok(())
            }
        }
    }

    /// Removes one name: opened relative to its parent, as the link itself, never by identifier.
    fn remove_by_name(
        &mut self,
        dir: &DirHandle,
        child: &Child,
        path: &str,
    ) -> Result<(), RootError> {
        let started = Instant::now();
        loop {
            match dir.open_name(&child.name, DELETE, true) {
                Ok(handle) => {
                    if let Err(failure) = delete(&handle) {
                        self.leave(
                            path,
                            format!("not removed (Windows error {})", failure.code),
                        );
                    }
                    return Ok(());
                }
                Err(failure) if failure.code == ERROR_SHARING_VIOLATION => {
                    if started.elapsed() >= IN_USE_WAIT {
                        self.leave(path, "in use");
                        return Ok(());
                    }
                    std::thread::sleep(RETRY_EVERY);
                }
                Err(failure) if failure.code == ERROR_ACCESS_DENIED => {
                    self.leave(path, "access denied");
                    return Ok(());
                }
                Err(failure) if is_gone(failure.code) => return Ok(()),
                Err(failure) => {
                    self.leave(path, format!("not opened (Windows error {})", failure.code));
                    return Ok(());
                }
            }
        }
    }
}

fn is_gone(code: u32) -> bool {
    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND};
    code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND
}

/// Opens a child for removal, waiting for a short while while another process has it open.
fn open_waiting(
    dir: &DirHandle,
    child: &Child,
    access: u32,
) -> Result<std::result::Result<super::walk::Opened, Lost>, RootError> {
    let started = Instant::now();
    loop {
        match dir.open_child(child, access)? {
            Err(Lost::Refused(code)) if code == ERROR_SHARING_VIOLATION => {
                if started.elapsed() >= IN_USE_WAIT {
                    return Ok(Err(Lost::Refused(code)));
                }
                std::thread::sleep(RETRY_EVERY);
            }
            other => return Ok(other),
        }
    }
}

/// Deletes the object behind the handle with POSIX semantics: the name goes at once, whatever
/// else has the object open, and the read-only attribute does not stop it. The handle must be
/// open with the right to delete.
fn delete(handle: &Handle) -> Result<(), super::ffi::Error> {
    let information = FILE_DISPOSITION_INFORMATION_EX {
        Flags: FILE_DISPOSITION_DELETE
            | FILE_DISPOSITION_POSIX_SEMANTICS
            | FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE,
    };
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: the handle is open with the right to delete, and the buffer is the structure the
    // class takes, of the size given.
    let status = unsafe {
        NtSetInformationFile(
            handle.raw(),
            &raw mut status_block,
            (&raw const information).cast::<c_void>(),
            size_of::<FILE_DISPOSITION_INFORMATION_EX>() as u32,
            FileDispositionInformationEx,
        )
    };
    if status < 0 {
        // SAFETY: converts a status code to a Windows error number; it reads nothing else.
        let code = unsafe { windows_sys::Win32::Foundation::RtlNtStatusToDosError(status) };
        return Err(error(code, "deleting an object"));
    }
    Ok(())
}

/// Checks that the disposition call works on this volume, on a scratch file made in `dir`, which
/// only administrators can write: the service refuses to start when it does not.
///
/// # Errors
///
/// Returns an error when the file cannot be made or the call does not delete it.
pub fn check_disposition(dir: &DirHandle) -> Result<(), RootError> {
    let name = format!("disposition-check-{}", random_name()?);
    let units: Vec<u16> = name.encode_utf16().collect();
    let handle = dir.create_file_named(&units, DELETE)?;
    delete(&handle)?;
    drop(handle);
    match dir.open_name(&units, 0, false) {
        Ok(_) => Err(RootError::Refused(
            "the platform's delete with POSIX semantics left the scratch file".to_owned(),
        )),
        Err(failure) if is_gone(failure.code) => Ok(()),
        Err(failure) => Err(failure.into()),
    }
}
