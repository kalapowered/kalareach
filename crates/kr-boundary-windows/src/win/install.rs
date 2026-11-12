//! The installation, its repair and its removal.
//!
//! The installation lays down, in this order and recording each object in the manifest before the
//! step that makes it: the data directory and the earlier-state record, the program directory and
//! the broker and credential helper in it, the two accounts with their rights, the service, the
//! Application Identity service, started and awaited until the platform reports its first policy
//! applied, the application-control policy, awaited the same way, and then the proof that the
//! policy refuses what it must. A failure at any step undoes what was done by the removal
//! sequence and then checks the machine against the earlier-state record.
//!
//! The removal puts back only what the installation changed. Another rule that an administrator
//! added to the executable collection is left in force, with the allow-all rule beside it, since
//! taking the allow-all rule away would make that rule a block for every account it does not name.
//! The broker stays up in a maintenance state until the release has been shown, because only the
//! broker can make the token that shows it.

#![allow(unsafe_code)]

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead as _, Read as _, Write as _};
use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use sha2::{Digest as _, Sha256};

use crate::filekey::FileKey;
use crate::frame::{self, Class, Request, Response};
use crate::manifest::{
    GitSet, Image, InstallState, Manifest, ObjectKind, Prior, STORE_VERSION, StoreError,
    git_version,
};
use crate::messages;
use crate::notice::NOTICE;
use crate::policy::{self, Policy};
use crate::records::{self, Records, is_hex32, is_manifest_replacement};
use crate::remedy::{self, EntryKind, Origin, ParentCure, Presence};

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_FOR_BACKUP_INTENT, FILE_OPEN_IF,
    FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile, NtSetSecurityObject,
};
use windows_sys::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, ERROR_INVALID_PARAMETER, ERROR_PATH_NOT_FOUND,
    ERROR_SHARING_VIOLATION, GetLastError, HANDLE, RtlNtStatusToDosError, UNICODE_STRING,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, FILE_ADD_SUBDIRECTORY, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_TAG_INFO, FILE_CASE_SENSITIVE_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_ID_128,
    FILE_ID_INFO, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FileAttributeTagInfo, FileCaseSensitiveInfo, FileIdInfo,
    GetFileInformationByHandleEx, GetFileSizeEx, OPEN_EXISTING,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

use super::acl;
use super::applocker::{self, Channel};
use super::broker::PROOF_BOUND;
use super::ffi::{self, Sid};
use super::fresh;
use super::proof;
use super::registry;
use super::sd::{self, Principals, SdKind};
use super::service;
use super::walk::{AnchorRefusal, DirHandle, Kind, LIST, Lost, Opened};
use super::{account, boot, pipe, token, verify};

/// The broker's service name.
pub const SERVICE: &str = "KalaReachBoundary";
/// The checkout and apply account.
pub const CHECKOUT: &str = "krb-checkout";
/// The connection account.
pub const CONNECT: &str = "krb-connect";

const DISPLAY: &str = "KalaReach repository boundary";
const BROKER: &str = "kr-boundary-broker.exe";
/// The name of Git's global configuration in the directory of its empty settings.
const GIT_CONFIG: &str = "config";
const CREDENTIAL: &str = "kr-boundary-credential.exe";
/// The privileges the broker uses and no others: the service manager gives the service's token
/// these and takes away every other.
pub const BROKER_PRIVILEGES: [&str; 7] = [
    "SeTcbPrivilege",
    "SeAssignPrimaryTokenPrivilege",
    "SeIncreaseQuotaPrivilege",
    "SeImpersonatePrivilege",
    "SeChangeNotifyPrivilege",
    // Held disabled, and enabled only on the token of the thread that walks a tree (privilege.rs).
    "SeBackupPrivilege",
    "SeRestorePrivilege",
];
const APPID: &str = "AppIDSvc";
const APPID_KEY: &str = r"SYSTEM\CurrentControlSet\Services\AppIDSvc";
const AUTOMATIC: u32 = 2;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const READ_CONTROL: u32 = 0x0002_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;
const WRITE_DAC: u32 = 0x0004_0000;

/// A failure of the installation, its repair or its removal.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The installation refuses to go on, for a reason the person can act on.
    #[error("{0}")]
    Refused(String),
    /// A call into the platform failed.
    #[error(transparent)]
    Win(#[from] ffi::Error),
    /// A record could not be read or written.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// Application control could not be read or written.
    #[error(transparent)]
    Applocker(#[from] applocker::Error),
    /// A file operation failed.
    #[error("{what}: {source}")]
    Io {
        /// What was being done.
        what: String,
        /// The reason.
        source: io::Error,
    },
    /// A step failed in a way that is not one of the above.
    #[error("{0}")]
    Failed(String),
}

/// The steps of an installation, named so that a test can make any one of them fail.
pub const STEPS: [&str; 7] = [
    "directories",
    "payload",
    "accounts",
    "service",
    "appid",
    "policy",
    "broker",
];

/// Fails the step named in the environment, for the test build only. A build that ships has no
/// such seam.
#[cfg(feature = "testing")]
fn inject(step: &str) -> Result<(), Error> {
    if std::env::var("KR_BOUNDARY_FAIL_AFTER").as_deref() == Ok(step) {
        return Err(Error::Failed(format!(
            "a failure was injected after the {step} step"
        )));
    }
    Ok(())
}

#[cfg(not(feature = "testing"))]
#[allow(clippy::unnecessary_wraps)]
fn inject(_step: &str) -> Result<(), Error> {
    Ok(())
}

/// Records a call that the installation makes on the Application Identity service, in the file
/// that `KR_BOUNDARY_CALL_LOG` names, for the test build only, so that a case can show what was
/// asked of the service manager. A build that ships records nothing.
#[cfg(feature = "testing")]
fn note_call(call: &str) {
    if let Some(path) = std::env::var_os("KR_BOUNDARY_CALL_LOG")
        && let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path)
    {
        let _ = writeln!(file, "{call}");
    }
}

#[cfg(not(feature = "testing"))]
fn note_call(_call: &str) {}

/// Seams for the test build only: a function that a case hands over runs where another program
/// would act, so that the case shows what the installation does then. A build that ships has none.
#[cfg(feature = "testing")]
pub mod testing {
    use std::sync::{Mutex, PoisonError};

    type Hook = Box<dyn FnOnce() + Send>;

    static AFTER_A_READ: Mutex<Option<Hook>> = Mutex::new(None);
    static RAN_AFTER: Mutex<Option<&'static str>> = Mutex::new(None);

    /// Runs the function once, right after the first of the two reads that decide which private
    /// roots are in use, whichever of them comes first: the listing of `run`, and the read of the
    /// journal. A broker that begins an invocation then writes its intent row and makes its root
    /// between the two reads. With the roots listed first and the journal read after, as the
    /// installation does, the function runs after the listing; read the other way round, it runs
    /// after the journal's read, and [`listing_the_function_ran_after`] tells which.
    pub fn after_the_first_of_the_two_reads(hook: impl FnOnce() + Send + 'static) {
        *RAN_AFTER.lock().unwrap_or_else(PoisonError::into_inner) = None;
        *AFTER_A_READ.lock().unwrap_or_else(PoisonError::into_inner) = Some(Box::new(hook));
    }

    /// The read the function ran after (`run` for the listing of the roots, `journal` for the read
    /// of the journal), or none while it has not run.
    pub fn listing_the_function_ran_after() -> Option<&'static str> {
        *RAN_AFTER.lock().unwrap_or_else(PoisonError::into_inner)
    }

    static AFTER_THE_INSPECTION: Mutex<Option<Hook>> = Mutex::new(None);

    /// Runs the function once, right after the removal has inspected the data directory and before
    /// it decides what to do: a directory that something made after the inspection found none
    /// there is then there, as it is on a machine where an ordinary account made it in between.
    pub fn after_the_removal_inspects_the_data_directory(hook: impl FnOnce() + Send + 'static) {
        *AFTER_THE_INSPECTION
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(Box::new(hook));
    }

    pub(super) fn after_the_removal_inspection() {
        let hook = AFTER_THE_INSPECTION
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(hook) = hook {
            hook();
        }
    }

    pub(super) fn after_a_read(read: &'static str) {
        let hook = AFTER_A_READ
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(hook) = hook {
            hook();
            *RAN_AFTER.lock().unwrap_or_else(PoisonError::into_inner) = Some(read);
        }
    }
}

/// The calls the installation makes on the Application Identity service, each one recorded in the
/// test build. A machine-wide control that the machine's owner may have a policy in force through:
/// the installation starts it where it is stopped and stops it, in the removal, only where the
/// installation started it.
struct Identity<'a>(&'a service::Service);

impl Identity<'_> {
    fn set_automatic(&self) -> Result<(), Error> {
        note_call("appid set-automatic");
        Ok(self.0.set_automatic()?)
    }

    fn start(&self) -> Result<(), Error> {
        note_call("appid start");
        self.0.start()?;
        Ok(self.0.wait_for(false, Duration::from_secs(60))?)
    }

    fn stop(&self) -> Result<(), Error> {
        note_call("appid stop");
        self.0.stop()?;
        Ok(self.0.wait_for(true, Duration::from_secs(60))?)
    }
}

fn io_error(what: impl Into<String>) -> impl FnOnce(io::Error) -> Error {
    let what = what.into();
    move |source| Error::Io { what, source }
}

/// Where the installation lives.
#[derive(Clone, Debug)]
pub struct Paths {
    /// The program directory: the broker and the credential helper.
    pub program: PathBuf,
    /// The highest folder above the program directory that is read before anything in it is used:
    /// `Program Files`. Every folder from it down to the program directory's parent is checked.
    pub program_top: PathBuf,
    /// The data directory: the manifest, the earlier-state record, the journal and the staging
    /// directories.
    pub data: PathBuf,
    /// The journal's directory, one file for each invocation. Only administrators and the system
    /// can reach it.
    pub journal: PathBuf,
    /// The directory every invocation's private root is made under. No boundary account can list,
    /// create in or delete from it.
    pub run: PathBuf,
    /// What the broker points Git's global file, hooks path and template directory at: an empty
    /// `config`, an empty `hooks` and an empty `template`, which every account may read.
    pub git: PathBuf,
    /// The directory a run stages in, only administrators and the system can write.
    pub staging: PathBuf,
    /// The manifest.
    pub manifest: PathBuf,
    /// The earlier-state record.
    pub prior: PathBuf,
}

impl Paths {
    /// The folder above the data directory, which the installation makes with its own protected
    /// list and which no account but the system's may own, write in, delete in or change.
    #[must_use]
    pub fn data_parent(&self) -> &Path {
        self.data.parent().unwrap_or(&self.data)
    }

    /// The installation's places on this computer, from the system's own known folders.
    ///
    /// # Errors
    ///
    /// Returns the platform's error when a known folder cannot be read: no fixed folder takes its
    /// place, since a computer's system can be on another drive.
    pub fn system() -> Result<Paths, Error> {
        let program_files = ffi::known_folder(ffi::KnownFolder::ProgramFiles)?;
        let program_data = ffi::known_folder(ffi::KnownFolder::ProgramData)?;
        let data = program_data.join("KalaReach").join("Boundary");
        let program = program_files.join("KalaReach").join("Boundary");
        Ok(Paths {
            git: program.join("git"),
            program_top: program_files,
            program,
            staging: data.join("staging"),
            journal: data.join("journal"),
            run: data.join("run"),
            manifest: data.join("manifest.json"),
            prior: data.join("prior.json"),
            data,
        })
    }
}

fn git_dir() -> Result<PathBuf, Error> {
    Ok(ffi::known_folder(ffi::KnownFolder::ProgramFiles)?.join("Git"))
}

/// How the installation was found.
pub enum Entry {
    /// Nothing of the installation exists.
    Fresh,
    /// The manifest says the installation finished.
    Installed(Manifest),
    /// The manifest says an installation began and did not finish.
    Partial(Manifest),
}

fn say(line: &str) {
    println!("{line}");
}

/// Finds what state the computer is in, and refuses when an object of the installation's names
/// exists that the manifest does not list.
///
/// # Errors
///
/// Returns [`Error::Refused`] naming the foreign object, or the failure of the call that looked.
pub fn entry(paths: &Paths) -> Result<Entry, Error> {
    // What the data directory holds is read on handles before any of it is used: the manifest
    // decides what a repair or a removal touches, so it is read only after the directory it is in
    // and everything beside it passed their checks.
    let inspected = match check_data_parent(paths)? {
        Some(parent) => inspect_existing_data(paths, &parent)?.map(|(_, inspected)| inspected),
        None => None,
    };
    // A data directory that passed its inspection is the installation's own: with no manifest it is
    // an empty one, which a new installation takes as it is.
    let data_accepted = inspected.is_some();
    if let Some(manifest) = inspected.and_then(|inspected| inspected.manifest) {
        check_program_directory(paths)?;
        return Ok(match manifest.state {
            InstallState::Installed => Entry::Installed(manifest),
            InstallState::InProgress => Entry::Partial(manifest),
        });
    }
    for name in [CHECKOUT, CONNECT] {
        if account::find(name).is_some() {
            return Err(Error::Refused(format!(
                "an account named {name} exists and this installation did not make it"
            )));
        }
    }
    if service::manager()?.open(SERVICE)?.is_some() {
        return Err(Error::Refused(format!(
            "a service named {SERVICE} exists and this installation did not make it"
        )));
    }
    for (directory, accepted) in [(&paths.program, false), (&paths.data, data_accepted)] {
        if directory.exists() && !accepted {
            return Err(Error::Refused(format!(
                "{} exists and this installation did not make it",
                directory.display()
            )));
        }
    }
    Ok(Entry::Fresh)
}

/// Makes a directory with its descriptor unless one is there: what is there was checked on its
/// handle when the installation was entered.
fn made_if_missing(path: &Path, readable: &Principals, what: &str) -> Result<(), Error> {
    if path.exists() {
        return Ok(());
    }
    fresh::directory_at(path, SdKind::AdminDir, readable).map_err(io_error(what))
}

/// Puts a program file in the program directory: made new with its descriptor when it is not there;
/// a file that an earlier run of this installation put there was checked on its handle when the
/// installation was entered, and is overwritten as it is, keeping the descriptor that was checked.
fn install_program_file(source: &Path, target: &Path) -> io::Result<()> {
    let mut from = fs::File::open(source)?;
    if target.exists() {
        let mut to = OpenOptions::new().write(true).truncate(true).open(target)?;
        io::copy(&mut from, &mut to)?;
        return to.sync_all();
    }
    let mut to = fresh::file_at(target, SdKind::ProgramFile, true)?;
    io::copy(&mut from, &mut to)?;
    to.sync_all()
}

/// Opens the folder above the data directory once, checks it on that handle and keeps the handle,
/// or says the folder is not there. The folder is opened without following a reparse point, with a
/// data right and without sharing the right to delete or rename it, so that nobody who already holds
/// a handle with that right can swap the folder after the check (the open then fails), and nobody
/// can begin to hold one while this handle is open. The attributes and the permissions are read from
/// the handle itself, so they are those of the object the caller holds.
///
/// The folder is refused when it is a link or not a folder, when an account other than the system's
/// own class (the system, the administrators, the installer service and the creator-owner
/// placeholder) owns it, when another account may write, delete in or change it, when its list has
/// an entry of a type the check does not read, and when another program holds it open with a right
/// to delete it or that does not share it. Whoever owns or may change the folder can rename the data directory away and put a
/// manifest, a journal and a directory of private roots of their own in its place, which the
/// broker, running as the system, would read by path. A folder that an earlier installation made
/// with an inherited list is refused the same way, since nothing of the earlier form is kept.
///
/// # Errors
///
/// Returns [`Error::Refused`] naming the reason, or the failure of the call that looked.
pub fn check_data_parent(paths: &Paths) -> Result<Option<ffi::Handle>, Error> {
    let parent = paths.data_parent();
    let wide = ffi::wide_path(parent);
    // SAFETY: the path is NUL-terminated; the call keeps nothing of it.
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_LIST_DIRECTORY | FILE_ADD_SUBDIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    let handle = match ffi::Handle::new(raw, "opening the data directory's parent folder") {
        Ok(handle) => handle,
        Err(failure)
            if failure.code == ERROR_FILE_NOT_FOUND || failure.code == ERROR_PATH_NOT_FOUND =>
        {
            return Ok(None);
        }
        Err(failure) if failure.code == ERROR_SHARING_VIOLATION => {
            return Err(parent_refusal(
                paths,
                "another program holds it open: with a right to delete or rename it, or without sharing it for reading and writing, and the check needs both so that it can hold the folder against a rename or a delete",
                ParentCure::Close,
            ));
        }
        // Nothing shows who made a folder that cannot be opened: it is moved aside, never corrected
        // into place and never removed.
        Err(failure) => {
            return Err(parent_refusal(
                paths,
                &format!("it could not be opened to be checked ({failure})"),
                ParentCure::Unreadable,
            ));
        }
    };
    let mut tag = FILE_ATTRIBUTE_TAG_INFO {
        FileAttributes: 0,
        ReparseTag: 0,
    };
    // SAFETY: the handle is open and the record is the size the class takes.
    if unsafe {
        GetFileInformationByHandleEx(
            handle.raw(),
            FileAttributeTagInfo,
            (&raw mut tag).cast(),
            size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    } == 0
    {
        return Err(ffi::last("reading the data directory's parent folder").into());
    }
    if tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
    {
        return Err(parent_refusal(
            paths,
            "it is a link or not a folder",
            ParentCure::MoveAside,
        ));
    }
    if let Some(finding) = acl::changeable_by_others_on(&handle, false)? {
        // The handle's own owner tells whether the system's class made the folder.
        let cure = if check_owner(&handle)?.is_some() {
            ParentCure::MoveAside
        } else {
            ParentCure::Correct(presence_of(&paths.data))
        };
        return Err(parent_refusal(paths, &finding, cure));
    }
    Ok(Some(handle))
}

fn presence_of(path: &Path) -> Presence {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Presence::Present,
        Err(error) if error.kind() == io::ErrorKind::NotFound => Presence::Absent,
        Err(error) => Presence::Unknown(error.to_string()),
    }
}

/// The refusal of a folder above the data directory: what the folder is, why it is refused and what
/// to do.
fn parent_refusal(paths: &Paths, why: &str, cure: ParentCure) -> Error {
    let parent = paths.data_parent();
    let remedy = remedy::parent_advice(&cure);
    Error::Refused(format!(
        "{} is the folder that holds the boundary's data (its manifest, its journal and the roots of its operations). It is refused because {why}. Whoever owns that folder, or can write or delete in it, could put data of their own in its place while the broker runs as the system. {remedy}",
        parent.display()
    ))
}

/// The directories the installation makes directly in its data directory, each with the descriptor
/// of its own and each recorded in the manifest before it is made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataChild {
    /// Where a run stages and where the proof's scratch directories are made.
    Staging,
    /// The journal's directory, one file for each invocation.
    Journal,
    /// The directory every invocation's private root is made under.
    Run,
}

impl DataChild {
    fn path(self, paths: &Paths) -> &Path {
        match self {
            DataChild::Staging => &paths.staging,
            DataChild::Journal => &paths.journal,
            DataChild::Run => &paths.run,
        }
    }

    fn name(self, paths: &Paths) -> OsString {
        self.path(paths).file_name().unwrap_or_default().to_owned()
    }
}

/// The folder above the data directory, the data directory itself and the directories directly
/// beneath it, each opened relative to the held directory. Each is held from the check, or from the
/// call that made it, until the steps that give the directories their lists are done. The steps
/// that follow go by path in those directories, where only the system and the administrators may
/// add, rename or delete anything: a file that another program reads by path is made new there,
/// with its descriptor in the call that makes it, and every other entry was checked on its own
/// handle before.
///
/// None of these handles lets another program rename or delete what it holds (they share read and
/// write only). Every list the installation changes in the data directory is changed on one of these
/// handles and never by path: a path can name another object a moment later, and the platform's
/// change by path follows a link and rewrites the tree it leads to.
pub struct DataHolds {
    paths: Paths,
    _parent: ffi::Handle,
    data: DirHandle,
    staging: Option<DirHandle>,
    journal: Option<DirHandle>,
    run: Option<DirHandle>,
}

impl std::fmt::Debug for DataHolds {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("DataHolds").finish_non_exhaustive()
    }
}

impl DataHolds {
    /// Gives the data directory the installation's protected list, on the handle held since the
    /// directory was made or checked. The call propagates to nothing: what the directory holds is
    /// given its list by the steps that make it.
    ///
    /// # Errors
    ///
    /// Returns the platform's error when the list is refused.
    pub fn protect(&self) -> Result<(), Error> {
        protect_handle(
            self.data.handle(),
            &data_descriptor()?,
            "the data directory",
        )
    }

    /// Makes the directory beneath the data directory, relative to the held directory and in one
    /// call that carries its protected list, or takes the one that is there: a directory that is
    /// there was opened and checked on its own handle (its owner, every entry of its list, no link)
    /// before this, and now gets the list on that handle. A link at its name is opened as the link,
    /// refused, and the tree it leads to is not touched.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Refused`] naming the reason when what is there is not the installation's
    /// own, and the platform's error when a call fails.
    pub fn directory(&mut self, which: DataChild) -> Result<(), Error> {
        let descriptor = sd::descriptor(SdKind::AdminDir, &Principals::default())?;
        let slot = match which {
            DataChild::Staging => &mut self.staging,
            DataChild::Journal => &mut self.journal,
            DataChild::Run => &mut self.run,
        };
        if let Some(held) = slot {
            return protect_handle(
                held.handle(),
                &descriptor,
                &which.path(&self.paths).display().to_string(),
            );
        }
        let name = which.name(&self.paths);
        let (handle, created) = open_directory_relative(
            self.data.handle(),
            &name,
            FILE_OPEN_IF,
            Some(&descriptor),
            LIST | WRITE_DAC,
        )?
        .ok_or_else(|| {
            Error::Failed(format!(
                "{} was made and is gone again",
                which.path(&self.paths).display()
            ))
        })?;
        let shown = which.path(&self.paths).display().to_string();
        if let Some(why) = not_a_plain_directory(&handle, &shown)? {
            return Err(child_refusal(&self.paths, &name, why, &Origin::Foreign));
        }
        if !created {
            // It appeared between the listing and this call: it is checked like one that was there.
            if let Some(why) = check_held_object(&handle)? {
                return Err(child_refusal(&self.paths, &name, &why, &origin_of(&handle)));
            }
            protect_handle(&handle, &descriptor, &shown)?;
        }
        *slot = Some(held_directory(handle)?);
        Ok(())
    }
}

/// The descriptor the data directory is made with and given: owned by the administrators, with a
/// protected list that names the system and the administrators alone.
fn data_descriptor() -> Result<sd::OwnedSd, Error> {
    Ok(sd::descriptor(SdKind::DataParent, &Principals::default())?)
}

/// The words the refusal of the data directory itself ends with when its handle shows the system's
/// class as its owner: what the administrator does. Nothing the installation recorded is removed.
const DATA_REMEDY: &str = "Make the Administrators group its owner and leave the system and the Administrators group as the only entries of its list, then run the setup program again. The manifest and the journal stay where they are.";

/// The words the refusal of a data directory ends with when its handle shows that the installation
/// did not make it (another account owns it, or it is a link or not a directory).
const DATA_NOT_MADE: &str = "The handle of this directory shows that the installation did not make it, and it can hold files that another account wrote. Do not correct its content into place unless you know that your own installation wrote it, and do not remove it. Move it aside (rename it, which keeps everything in it), then run the setup program again: the installation makes the directory new.";

/// The words the refusal of a data directory ends with when its list refuses the open, or the open
/// failed for a reason that shows nothing: the installation's lists never refuse the administrator,
/// so it did not make a directory whose list does, and nothing is known of one that cannot be read.
const DATA_UNKNOWN: &str = "Nothing shows that the installation made this directory, because its own list refuses the check or it could not be read, and it can hold files that another account wrote. Do not correct its owner or its list, and do not remove it. Move it aside (rename it, which keeps everything in it), then run the setup program again: the installation makes the directory new.";

/// The words the refusal of a data directory ends with when a program holds it open.
const DATA_UNREADABLE: &str = "Nothing shows who made this directory, because it could not be read. Do not correct its owner or its list, and do not remove it: either would hide what it is. Close the program that holds it open, then run the setup program again, which reads it again.";

/// The words the refusal of a data directory that separates names by case ends with, when the
/// system's class owns it.
const CASE_REMEDY: &str = "Turn the flag off (`fsutil.exe file setCaseSensitiveInfo <the directory> disable`), then run the setup program again. The manifest and the journal stay where they are.";

/// Why a data directory is refused when it separates names that differ only by case.
const CASE_SENSITIVE_WHY: &str = "it separates names that differ only by case, and the installation compares names without regard to case";

/// The refusal of a data directory that is there and is not the installation's own. The remedy comes
/// from what the directory's own handle showed, and one refusal gives one remedy.
fn data_refusal(paths: &Paths, why: &str, origin: &Origin) -> Error {
    let remedy = match origin {
        Origin::Foreign => DATA_NOT_MADE,
        Origin::Held(_) => DATA_UNREADABLE,
        Origin::Refused(_) | Origin::Unknown(_) => DATA_UNKNOWN,
        Origin::System if why == CASE_SENSITIVE_WHY => CASE_REMEDY,
        Origin::System => DATA_REMEDY,
    };
    Error::Refused(format!(
        "{} is the boundary's data directory (its manifest, its journal and the roots of its operations). It is refused because {why}. Whoever owns it, or can change its list, could put data of their own in it while the broker runs as the system. {remedy}",
        paths.data.display()
    ))
}

/// The refusal of a data directory that could not be opened or read: a program that holds it open,
/// a list that refuses the check, or another failure, each with the one remedy its error shows. Any
/// other kind of failure is returned as it is.
fn data_failure(paths: &Paths, error: Error) -> Error {
    match error {
        Error::Win(failure) => {
            let why = format!("it could not be opened to be checked ({failure})");
            let origin = remedy::origin_of_open_error(failure.code, &failure.to_string());
            data_refusal(paths, &why, &origin)
        }
        other => other,
    }
}

/// The refusal of what is inside the data directory: a child that is not the installation's own, or
/// is not what the manifest says.
fn child_refusal(paths: &Paths, name: &OsStr, why: &str, origin: &Origin) -> Error {
    entry_refusal(paths, &paths.data, name, why, origin)
}

/// The refusal of an entry that the layout never gives as a record (a name it does not give, what is
/// in `staging`, a directory that no manifest records): it holds nothing the manifest and the
/// journal say, so it is named to remove, whatever its handle shows.
fn removal_refusal(paths: &Paths, dir: &Path, name: &OsStr, why: &str) -> Error {
    refusal_with(paths, dir, name, why, EntryKind::Other, &Origin::System)
}

/// What the layout makes of the name in the directory: the manifest, the earlier-state record, a
/// replacement of the manifest and the three directories in the data directory, a journal file in
/// `journal`, and a private root in `run` (`named_root` says whether a journal names it as unfinished
/// work). What is in `staging`, and any other name, is never a record.
fn kind_of(paths: &Paths, dir: &Path, name: &OsStr, named_root: bool) -> EntryKind {
    let text = name.to_string_lossy();
    if dir == paths.data {
        let names = data_child_names(paths);
        let given = |index: usize| names[index].0.to_string_lossy().eq_ignore_ascii_case(&text);
        if given(0) {
            EntryKind::Manifest
        } else if given(1) {
            EntryKind::Prior
        } else if given(2) {
            EntryKind::Staging
        } else if given(3) {
            EntryKind::Journal
        } else if given(4) {
            EntryKind::Run
        } else if is_manifest_replacement(&text) {
            EntryKind::Replacement
        } else {
            EntryKind::Other
        }
    } else if dir == paths.journal && is_journal_file_name(&text) {
        EntryKind::JournalFile
    } else if dir == paths.run && is_hex32(&text) {
        if named_root {
            EntryKind::NamedRoot
        } else {
            EntryKind::UnnamedRoot
        }
    } else {
        EntryKind::Other
    }
}

/// What an object's own handle shows about who made it: an owner of the system's class is the
/// installation's own, any other owner is another account's, and an owner that cannot be read
/// leaves it unknown. A link, a second name for a file and an object of the wrong kind are not read
/// here: the caller has them from the same handle, and each is never the installation's own.
fn origin_of(handle: &ffi::Handle) -> Origin {
    match sd::summary_of_handle(handle) {
        Ok(summary) if [SYSTEM, ADMINISTRATORS].contains(&summary.owner.as_str()) => Origin::System,
        Ok(_) => Origin::Foreign,
        Err(error) => Origin::Unknown(error.to_string()),
    }
}

/// What an opened entry's handle shows about who made it: a link or a file with a second name is
/// not the installation's, and any other object is read for its owner.
fn origin_of_opened(opened: &Opened) -> Origin {
    if opened.kind == Kind::ReparsePoint || (opened.kind == Kind::File && opened.links > 1) {
        Origin::Foreign
    } else {
        origin_of(&opened.handle)
    }
}

/// What the loss of a child shows: a list that refuses the administrator, a program that holds the
/// child, or nothing. A child that is gone since the listing is the caller's to treat as absent.
fn origin_of_lost(lost: &Lost) -> Origin {
    match lost {
        Lost::Refused(code) => remedy::origin_of_open_error(*code, &lost.to_string()),
        other => Origin::Unknown(other.to_string()),
    }
}

/// The refusal of one entry in a directory of the installation. The remedy comes from what the
/// entry's own handle showed (`origin`) and from the lookup of the manifest, and never from the
/// words of the reason: for a name the layout gives as a record, the system's class's own is
/// corrected while a manifest may be there, another account's is moved out, and one that could not
/// be read is neither corrected nor removed; any other name, and what is in `staging`, is named to
/// remove.
fn entry_refusal(paths: &Paths, dir: &Path, name: &OsStr, why: &str, origin: &Origin) -> Error {
    refusal_with(
        paths,
        dir,
        name,
        why,
        kind_of(paths, dir, name, true),
        origin,
    )
}

/// The refusal of a private root that no journal names: its own handle decides, and only one that
/// the system's class owns is named to remove.
fn unnamed_root_refusal(
    paths: &Paths,
    dir: &Path,
    name: &OsStr,
    why: &str,
    origin: &Origin,
) -> Error {
    refusal_with(
        paths,
        dir,
        name,
        why,
        kind_of(paths, dir, name, false),
        origin,
    )
}

fn refusal_with(
    paths: &Paths,
    dir: &Path,
    name: &OsStr,
    why: &str,
    kind: EntryKind,
    origin: &Origin,
) -> Error {
    let entry = dir.join(name);
    let manifest = presence_of(&paths.manifest);
    let remedy = remedy::choose(kind, origin, &manifest);
    let ending = remedy::ending(&entry, remedy, origin, kind, &manifest);
    Error::Refused(format!(
        "{} is the boundary's data directory (its manifest, its journal and the roots of its operations). It is refused because of {}: {why}. Whatever is in it that another account made or can change could be read by the broker, running as the system, as its own. {ending}",
        paths.data.display(),
        entry.display(),
    ))
}

const SYSTEM: &str = "S-1-5-18";
const ADMINISTRATORS: &str = "S-1-5-32-544";

/// The reason the installation cannot compare a directory's names as it does: the directory takes
/// two names that differ only by case for two entries, and the listing and the checks here take
/// them for one. A platform that has no such flag has no such directory.
fn case_sensitive_reason(handle: &ffi::Handle) -> Result<Option<String>, Error> {
    let mut info = FILE_CASE_SENSITIVE_INFO { Flags: 0 };
    // SAFETY: the handle is open and the record is the size the class takes.
    if unsafe {
        GetFileInformationByHandleEx(
            handle.raw(),
            FileCaseSensitiveInfo,
            (&raw mut info).cast(),
            size_of::<FILE_CASE_SENSITIVE_INFO>() as u32,
        )
    } == 0
    {
        // SAFETY: reads the calling thread's last error.
        let code = unsafe { GetLastError() };
        if code == ERROR_INVALID_PARAMETER {
            return Ok(None);
        }
        return Err(ffi::error(
            code,
            "reading whether the data directory separates names by case",
        )
        .into());
    }
    // The flag that says the directory separates names that differ only by case.
    const CASE_SENSITIVE_DIRECTORY: u32 = 1;
    Ok((info.Flags & CASE_SENSITIVE_DIRECTORY != 0).then(|| CASE_SENSITIVE_WHY.to_owned()))
}

/// What the data directory itself must be on its handle: a directory that compares names without
/// regard to case, and the installation's own.
fn check_data_object(handle: &ffi::Handle) -> Result<Option<String>, Error> {
    if let Some(why) = case_sensitive_reason(handle)? {
        return Ok(Some(why));
    }
    check_held_object(handle)
}

/// What an object that is held open must be, read on its own handle: the system's own class owns
/// it and no other account has any right on it, now or by inheritance; its owner is the system or the
/// administrators, and every entry of its list names one of the two. Returns the reason when it is
/// not.
fn check_held_object(handle: &ffi::Handle) -> Result<Option<String>, Error> {
    if let Some(finding) = acl::changeable_by_others_on(handle, false)? {
        return Ok(Some(finding));
    }
    let summary = sd::summary_of_handle(handle)?;
    if ![SYSTEM, ADMINISTRATORS].contains(&summary.owner.as_str()) {
        return Ok(Some(format!("it is owned by {}", summary.owner)));
    }
    let Some(entries) = summary.entries else {
        return Ok(Some("it has no permission list".to_owned()));
    };
    Ok(entries
        .iter()
        .find(|entry| ![SYSTEM, ADMINISTRATORS].contains(&entry.sid.as_str()))
        .map(|entry| format!("its permission list has an entry for {}", entry.sid)))
}

/// Gives a held directory the descriptor's protected list, on the handle. Nothing is propagated.
fn protect_handle(handle: &ffi::Handle, descriptor: &sd::OwnedSd, what: &str) -> Result<(), Error> {
    // SAFETY: the handle is open with the right to change the list, and the descriptor lives
    // through the call.
    let status = unsafe {
        NtSetSecurityObject(
            handle.raw(),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor.as_ptr(),
        )
    };
    if status < 0 {
        // SAFETY: converts a status the platform just returned.
        let code = unsafe { RtlNtStatusToDosError(status) };
        return Err(ffi::error(code, format!("setting the permissions of {what}")).into());
    }
    Ok(())
}

/// What the platform says of an open object's attributes.
fn attributes_of(handle: &ffi::Handle, what: &str) -> Result<u32, Error> {
    let mut tag = FILE_ATTRIBUTE_TAG_INFO {
        FileAttributes: 0,
        ReparseTag: 0,
    };
    // SAFETY: the handle is open and the record is the size the class takes.
    if unsafe {
        GetFileInformationByHandleEx(
            handle.raw(),
            FileAttributeTagInfo,
            (&raw mut tag).cast(),
            size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    } == 0
    {
        return Err(ffi::last(format!("reading {what}")).into());
    }
    Ok(tag.FileAttributes)
}

/// The reason an open object is not the plain directory the installation uses: it is a link, or it
/// is not a directory.
fn not_a_plain_directory(handle: &ffi::Handle, shown: &str) -> Result<Option<&'static str>, Error> {
    let attributes = attributes_of(handle, shown)?;
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Ok(Some("it is a link"));
    }
    if attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Ok(Some("it is not a directory"));
    }
    Ok(None)
}

/// The identity of an open object.
fn file_key(handle: &ffi::Handle) -> Result<FileKey, Error> {
    let mut info = FILE_ID_INFO {
        VolumeSerialNumber: 0,
        FileId: FILE_ID_128 {
            Identifier: [0; 16],
        },
    };
    // SAFETY: the handle is open and the record is the size the class takes.
    if unsafe {
        GetFileInformationByHandleEx(
            handle.raw(),
            FileIdInfo,
            (&raw mut info).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    } == 0
    {
        return Err(ffi::last("reading an object's identity").into());
    }
    Ok(FileKey {
        volume_serial: info.VolumeSerialNumber,
        file_id: info.FileId.Identifier,
    })
}

/// A directory that was opened for listing and for changing its list, as a held directory.
fn held_directory(handle: ffi::Handle) -> Result<DirHandle, Error> {
    let key = file_key(&handle)?;
    let attributes = attributes_of(&handle, "a directory")?;
    Ok(DirHandle::from_opened(Opened {
        handle,
        key,
        kind: Kind::Directory,
        attributes,
        links: 1,
    })?)
}

/// Opens, or makes, the directory `name` directly beneath `parent`, relative to the parent's handle
/// and never through a path, without following a reparse point: a link is opened as itself. With
/// [`FILE_OPEN_IF`] a directory that is not there is made in the same call with `descriptor` as its
/// own list, so that it is never there with a list it took from `parent`; with [`FILE_OPEN`] it is
/// only opened. The handle shares read and write only, so nothing renames or deletes the directory
/// while it is held. Returns the handle and whether this call made the directory, or none when
/// [`FILE_OPEN`] found nothing.
fn open_directory_relative(
    parent: &ffi::Handle,
    name: &OsStr,
    disposition: u32,
    descriptor: Option<&sd::OwnedSd>,
    access: u32,
) -> Result<Option<(ffi::Handle, bool)>, Error> {
    // The status that says the call made the directory.
    const FILE_CREATED: usize = 2;
    let units: Vec<u16> = name.encode_wide().collect();
    let text = UNICODE_STRING {
        Length: (units.len() * 2) as u16,
        MaximumLength: (units.len() * 2) as u16,
        Buffer: units.as_ptr().cast_mut(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.raw(),
        ObjectName: &raw const text,
        Attributes: 0,
        SecurityDescriptor: descriptor
            .map_or(std::ptr::null(), |made| made.as_ptr().cast_const().cast()),
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut raw: HANDLE = std::ptr::null_mut();
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: the name, the attributes, the descriptor and the status block live through the call,
    // the parent's handle is open, and the call keeps none of them.
    let status = unsafe {
        NtCreateFile(
            &raw mut raw,
            access | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
            &raw const attributes,
            &raw mut status_block,
            std::ptr::null(),
            FILE_ATTRIBUTE_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            disposition,
            FILE_DIRECTORY_FILE
                | FILE_OPEN_REPARSE_POINT
                | FILE_OPEN_FOR_BACKUP_INTENT
                | FILE_SYNCHRONOUS_IO_NONALERT,
            std::ptr::null(),
            0,
        )
    };
    if status < 0 {
        // SAFETY: converts a status the platform just returned.
        let code = unsafe { RtlNtStatusToDosError(status) };
        if disposition == FILE_OPEN
            && (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND)
        {
            return Ok(None);
        }
        return Err(ffi::error(
            code,
            format!(
                "opening {} beneath a held directory",
                name.to_string_lossy()
            ),
        )
        .into());
    }
    let handle = ffi::Handle::new(raw, "opening a directory beneath a held directory")?;
    Ok(Some((handle, status_block.Information == FILE_CREATED)))
}

/// What the data directory held that the installation made, read before any step used any of it.
struct Inspected {
    /// The manifest, read once everything in the directory had passed its check; none when the
    /// directory was empty.
    manifest: Option<Manifest>,
    staging: Option<DirHandle>,
    journal: Option<DirHandle>,
    run: Option<DirHandle>,
}

/// The names a directory directly in the data directory may have.
fn data_child_names(paths: &Paths) -> Vec<(OsString, Kind)> {
    let file = |path: &Path| path.file_name().unwrap_or_default().to_owned();
    vec![
        (file(&paths.manifest), Kind::File),
        (file(&paths.prior), Kind::File),
        (file(&paths.staging), Kind::Directory),
        (file(&paths.journal), Kind::Directory),
        (file(&paths.run), Kind::Directory),
    ]
}

/// Whether a journal's file name is one an invocation's journal has: 32 lowercase hexadecimal
/// digits and the extension.
fn is_journal_file_name(name: &str) -> bool {
    name.strip_suffix(".journal").is_some_and(|stem| {
        stem.len() == 32
            && stem
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    })
}

/// Reads what the data directory holds, on handles opened relative to the held directory, and
/// refuses unless every entry in it is one the installation made. An empty directory is accepted
/// (nothing records it, and nothing is in it). One that holds anything must hold the manifest, and
/// every entry must be a name the installation lays down: the manifest and the earlier-state
/// record as files, and the directories the manifest records, each as the kind it is, with no link
/// at its name, each opened on its own handle and checked there for its owner and every entry of its
/// list; the journal's directory holds only journal files, each checked the same way, and the
/// directory of the private roots only directories. The manifest is read last, after everything it
/// could lead the installation to use has passed, and it must record the data directory and each
/// directory in it.
fn inspect_data_directory(paths: &Paths, data: &DirHandle) -> Result<Inspected, Error> {
    let listed = data.children()?;
    let mut inspected = Inspected {
        manifest: None,
        staging: None,
        journal: None,
        run: None,
    };
    if listed.is_empty() {
        return Ok(inspected);
    }
    let names = data_child_names(paths);
    let expected_manifest = &names[0].0;
    if !listed
        .iter()
        .any(|child| same_name(&child.name, expected_manifest))
    {
        // With no manifest, the first entry is read on its own handle like every other record: a
        // name that the layout does not give is removed; one that it gives takes its remedy from
        // what the handle shows.
        let first = &listed[0];
        let shown = OsString::from_wide(&first.name);
        let kind = kind_of(paths, &paths.data, &shown, true);
        let origin = match kind {
            EntryKind::Other => Origin::System,
            _ => {
                let access = if matches!(
                    kind,
                    EntryKind::Staging | EntryKind::Journal | EntryKind::Run
                ) {
                    LIST | READ_CONTROL
                } else {
                    READ_CONTROL
                };
                match data.open_child(first, access)? {
                    Ok(opened) => origin_of_opened(&opened),
                    Err(lost) => origin_of_lost(&lost),
                }
            }
        };
        return Err(entry_refusal(
            paths,
            &paths.data,
            &shown,
            "no manifest records this directory, and a directory that no manifest records must be empty",
            &origin,
        ));
    }
    for child in &listed {
        let shown = OsString::from_wide(&child.name);
        let expected = match names.iter().find(|(name, _)| same_name(&child.name, name)) {
            Some((_, expected)) => expected,
            // A manifest that was being replaced when a run stopped.
            None if is_manifest_replacement(&shown.to_string_lossy()) => &Kind::File,
            None => {
                return Err(removal_refusal(
                    paths,
                    &paths.data,
                    &shown,
                    "the installation did not make it",
                ));
            }
        };
        let access = if *expected == Kind::Directory {
            LIST | WRITE_DAC
        } else {
            READ_CONTROL
        };
        let opened = match data.open_child(child, access)? {
            Ok(opened) => opened,
            // A child that is gone since the listing is absent, and nothing of it is left to check.
            Err(Lost::Gone) => continue,
            Err(lost) => {
                return Err(child_refusal(
                    paths,
                    &shown,
                    &format!("it could not be opened to be checked ({lost})"),
                    &origin_of_lost(&lost),
                ));
            }
        };
        match (opened.kind, *expected) {
            (Kind::ReparsePoint, _) => {
                return Err(child_refusal(
                    paths,
                    &shown,
                    "it is a link",
                    &Origin::Foreign,
                ));
            }
            (Kind::File, Kind::File) | (Kind::Directory, Kind::Directory) => {}
            (Kind::Directory, _) => {
                return Err(child_refusal(
                    paths,
                    &shown,
                    "it is a directory, not a file",
                    &Origin::Foreign,
                ));
            }
            (Kind::File, _) => {
                return Err(child_refusal(
                    paths,
                    &shown,
                    "it is a file, not a directory",
                    &Origin::Foreign,
                ));
            }
        }
        if opened.kind == Kind::File && opened.links > 1 {
            return Err(child_refusal(
                paths,
                &shown,
                "it has more than one name",
                &Origin::Foreign,
            ));
        }
        if let Some(why) = check_held_object(&opened.handle)? {
            return Err(child_refusal(
                paths,
                &shown,
                &why,
                &origin_of(&opened.handle),
            ));
        }
        if opened.kind == Kind::Directory {
            let held = DirHandle::from_opened(opened)?;
            let slot = if same_name(&child.name, &names[2].0) {
                &mut inspected.staging
            } else if same_name(&child.name, &names[3].0) {
                &mut inspected.journal
            } else {
                &mut inspected.run
            };
            *slot = Some(held);
        }
    }
    inspect_layout(
        paths,
        &paths.staging,
        inspected.staging.as_ref(),
        Layout::Staging,
    )?;
    inspect_layout(
        paths,
        &paths.journal,
        inspected.journal.as_ref(),
        Layout::Journal,
    )?;
    inspect_layout(paths, &paths.run, inspected.run.as_ref(), Layout::Run)?;
    let manifest = Manifest::load(&paths.manifest)?;
    let records = |path: &Path| {
        manifest
            .find(ObjectKind::Directory, &path.display().to_string())
            .is_some()
    };
    if !records(&paths.data) {
        return Err(child_refusal(
            paths,
            &names[0].0,
            "its manifest does not record this directory, and a directory that no manifest records must be empty",
            &Origin::System,
        ));
    }
    for (child, path) in [
        (&inspected.staging, &paths.staging),
        (&inspected.journal, &paths.journal),
        (&inspected.run, &paths.run),
    ] {
        if let Some(held) = child
            && !records(path)
            && !held.children()?.is_empty()
        {
            return Err(child_refusal(
                paths,
                path.file_name().unwrap_or_default(),
                "no manifest records this directory, and a directory that no manifest records must be empty",
                &Origin::System,
            ));
        }
    }
    inspected.manifest = Some(manifest);
    Ok(inspected)
}

/// Whether a listed name is the name the installation uses, as the platform compares them: without
/// regard to case.
fn same_name(listed: &[u16], name: &OsStr) -> bool {
    let wanted: Vec<u16> = name.encode_wide().collect();
    listed.len() == wanted.len()
        && listed.iter().zip(&wanted).all(|(left, right)| {
            let fold = |unit: u16| match u8::try_from(unit) {
                Ok(byte) => u16::from(byte.to_ascii_lowercase()),
                Err(_) => unit,
            };
            fold(*left) == fold(*right)
        })
}

/// What a directory beneath the data directory holds, by the layout the installation lays down.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Layout {
    /// An invocation's journal files, each a file with one name.
    Journal,
    /// The files that a step hands to another program by path (the policy, the program files
    /// before they are copied on), the directories of the proof's scratch space (each holds the
    /// one unlisted program and nothing else) and the temporary directories of PowerShell's runs.
    Staging,
    /// The private roots of the invocations, directories the broker made, each one that a journal
    /// names as unfinished work. The one exception to the rule that every entry is checked on its
    /// own handle: the installation does nothing inside a private root. Its contents and its list
    /// belong to the boundary's accounts by design and are walked only by the broker's removal, so
    /// a root is checked for its owner, its kind and its place alone.
    Run,
}

/// The kind of entry the layout names at a name, or none when the layout names nothing there.
fn layout_kind(layout: Layout, name: &str) -> Option<Kind> {
    let between = |prefix: &str, suffix: &str| {
        name.strip_prefix(prefix)
            .and_then(|rest| rest.strip_suffix(suffix))
            .is_some_and(is_hex32)
    };
    match layout {
        Layout::Journal => is_journal_file_name(name).then_some(Kind::File),
        Layout::Staging => {
            if between("policy-", ".xml") || between("payload-", ".exe") {
                Some(Kind::File)
            } else if between("proof-", "") || between("shell-", "") {
                Some(Kind::Directory)
            } else {
                None
            }
        }
        Layout::Run => is_hex32(name).then_some(Kind::Directory),
    }
}

/// How many directories deep an entry below a directory of the layout may be checked.
const WITHIN_DEPTH: usize = 8;

/// The reason an object is not the installation's own by its owner alone: the system or the
/// administrators own what the installation or the broker made.
fn check_owner(handle: &ffi::Handle) -> Result<Option<String>, Error> {
    let summary = sd::summary_of_handle(handle)?;
    Ok(
        (![SYSTEM, ADMINISTRATORS].contains(&summary.owner.as_str()))
            .then(|| format!("it is owned by {}", summary.owner)),
    )
}

/// The reason an object that every account may read is not the installation's own: another account
/// may change it, or the system and the administrators do not own it. The proof's scratch space is
/// made readable by every account, and what is made in it takes that list.
fn check_readable_object(handle: &ffi::Handle) -> Result<Option<String>, Error> {
    if let Some(finding) = acl::changeable_by_others_on(handle, false)? {
        return Ok(Some(finding));
    }
    check_owner(handle)
}

/// Reads every entry of a directory beneath the data directory on its own handle, opened relative
/// to the held directory: each must be one the layout names, of the kind it names, with no link at
/// its name and one name for a file, and owned and listed as the installation's own. Anything else
/// refuses the directory, and the refusal names the entry. A directory of the staging layout is
/// read to its depth, every entry in it checked the same way; a private root is only checked for its
/// owner, since its list names the invocation's own group.
fn inspect_layout(
    paths: &Paths,
    dir: &Path,
    held: Option<&DirHandle>,
    layout: Layout,
) -> Result<(), Error> {
    let Some(held) = held else {
        return Ok(());
    };
    let children = held.children()?;
    #[cfg(feature = "testing")]
    if layout == Layout::Run {
        testing::after_a_read("run");
    }
    // The roots are listed first and the journal is read after: the broker writes the intent row
    // before it makes a root, so a root that the listing shows is named by the journal read next,
    // also when the broker began its invocation between the two reads. Read the other way round, a
    // root made between the two reads would be listed and not named, and a root in use would be
    // refused.
    let named_roots = if layout == Layout::Run && !children.is_empty() {
        let named = roots_named_by_the_journal(paths)?;
        #[cfg(feature = "testing")]
        testing::after_a_read("journal");
        named
    } else {
        BTreeSet::new()
    };
    for child in children {
        let shown = OsString::from_wide(&child.name);
        let text = shown.to_string_lossy().into_owned();
        let Some(expected) = layout_kind(layout, &text) else {
            return Err(removal_refusal(
                paths,
                dir,
                &shown,
                "the installation does not give that name there",
            ));
        };
        if layout == Layout::Run && !named_roots.contains(&text) {
            // Its own handle decides: only a root that the system's class owns is named to remove.
            let origin = match held.open_child(&child, LIST | READ_CONTROL)? {
                Ok(opened) => origin_of_opened(&opened),
                Err(Lost::Gone) => continue,
                Err(lost) => origin_of_lost(&lost),
            };
            return Err(unnamed_root_refusal(
                paths,
                dir,
                &shown,
                "no journal names it as unfinished work, so the broker is not working in it",
                &origin,
            ));
        }
        let access = if expected == Kind::Directory {
            LIST | READ_CONTROL
        } else {
            READ_CONTROL
        };
        let opened = match held.open_child(&child, access)? {
            Ok(opened) => opened,
            Err(Lost::Gone) => continue,
            Err(lost) => {
                return Err(entry_refusal(
                    paths,
                    dir,
                    &shown,
                    &format!("it could not be opened to be checked ({lost})"),
                    &origin_of_lost(&lost),
                ));
            }
        };
        match (opened.kind, expected) {
            (Kind::ReparsePoint, _) => {
                return Err(entry_refusal(
                    paths,
                    dir,
                    &shown,
                    "it is a link",
                    &Origin::Foreign,
                ));
            }
            (Kind::File, Kind::File) | (Kind::Directory, Kind::Directory) => {}
            (Kind::Directory, _) => {
                return Err(entry_refusal(
                    paths,
                    dir,
                    &shown,
                    "it is a directory, not a file",
                    &Origin::Foreign,
                ));
            }
            (Kind::File, _) => {
                return Err(entry_refusal(
                    paths,
                    dir,
                    &shown,
                    "it is a file, not a directory",
                    &Origin::Foreign,
                ));
            }
        }
        if opened.kind == Kind::File && opened.links > 1 {
            return Err(entry_refusal(
                paths,
                dir,
                &shown,
                "it has more than one name",
                &Origin::Foreign,
            ));
        }
        let why = match (layout, opened.kind) {
            (Layout::Run, _) => check_owner(&opened.handle)?,
            (Layout::Staging, Kind::Directory) => check_readable_object(&opened.handle)?,
            _ => check_held_object(&opened.handle)?,
        };
        if let Some(why) = why {
            return Err(entry_refusal(
                paths,
                dir,
                &shown,
                &why,
                &origin_of(&opened.handle),
            ));
        }
        if layout == Layout::Staging && opened.kind == Kind::Directory {
            let inner = DirHandle::from_opened(opened)?;
            if text.starts_with("proof-") {
                inspect_proof_directory(paths, &dir.join(&shown), &inner)?;
            } else {
                inspect_within(paths, Scope::Staging, &dir.join(&shown), &inner, 1)?;
            }
        }
    }
    Ok(())
}

/// Which tree a check below the data directory or the program directory reads.
#[derive(Clone, Copy)]
enum Scope {
    /// A directory of `staging`: a refusal names the entry to remove.
    Staging,
    /// The program directory: a refusal names the owner and the list to correct.
    Program,
}

/// What cures a refusal of an entry in the program directory: each reason has a remedy that a
/// person can do, and a change of owner or list is the remedy only of the first.
#[derive(Clone, Copy)]
enum Cure {
    /// The owner or the list is wrong: correct them.
    OwnerAndList,
    /// The entry is not something the installation makes there (a link, a second name for a file,
    /// a name it does not give, a directory nested deeper than it makes anything): remove that
    /// entry.
    RemoveEntry,
    /// The configuration file that the installation makes empty holds settings: remove it, and a
    /// repair makes it again, empty. It is a name the installation gives there, so the text of
    /// [`Cure::RemoveEntry`] does not fit it.
    EmptyConfig,
    /// The entry could not be opened to be checked: another program holds it open or its list
    /// forbids the check.
    Open,
    /// The directory is on a volume that the installation does not use (not NTFS, on another
    /// computer, on removable media, or not an ordinary disk): neither a change of owner or list
    /// nor closing a program cures that.
    Volume,
}

/// The refusal of an entry below a directory of a scope.
fn within_refusal(
    paths: &Paths,
    scope: Scope,
    dir: &Path,
    name: &OsStr,
    why: &str,
    cure: Cure,
) -> Error {
    match scope {
        Scope::Staging => removal_refusal(paths, dir, name, why),
        Scope::Program => {
            let entry = dir.join(name);
            let remedy = match cure {
                Cure::OwnerAndList => "Make the Administrators group, or the system, its owner and leave the system and the Administrators group as the only accounts that may change it, then run the setup program again. Do not remove it: the manifest records it and stays where it is.".to_owned(),
                Cure::RemoveEntry => format!(
                    "Remove {}, and nothing else: it is not something that the installation makes there, and a change of its owner or its list does not cure that. A repair makes the program files again. Then run the setup program again.",
                    entry.display()
                ),
                Cure::EmptyConfig => format!(
                    "Remove {}, and nothing else: the installation makes it empty, and a configuration that holds settings would be read by the Git that the boundary's accounts run, and a change of its owner or its list does not cure that. A repair makes it again, empty. Then run the setup program again.",
                    entry.display()
                ),
                Cure::Volume => format!(
                    "{} is on a volume that the installation does not use: it keeps its program directory on a fixed, local NTFS volume, and nothing in it can be corrected to make another volume one. Do not remove the program directory: the manifest records it and stays where it is. Move the system's Program Files folder to such a volume, or install on a computer where it is on one, then run the setup program again.",
                    entry.display()
                ),
                Cure::Open => format!(
                    "Close the program that holds {} open, or correct who may open it, and if it is a link or not a folder remove that link or entry and nothing else, then run the setup program again. Do not remove the program directory: the manifest records it and stays where it is.",
                    entry.display()
                ),
            };
            Error::Refused(format!(
                "{} is the boundary's program directory (the program that the service runs as the system). It is refused because of {}: {why}. Whoever owns it, or can change its list, could replace that program. {remedy}",
                paths.program.display(),
                entry.display(),
            ))
        }
    }
}

/// Reads every existing folder from [`Paths::program_top`] down to the program directory's parent,
/// part by part: each opened on its own handle with no link followed, a plain folder at the place
/// that was asked for (its final path is the expected one), owned by the system, the Administrators
/// group or the installer service, with no entry that lets another account add to it, rename or
/// delete in it, write its list or take it. The paths that the service control manager runs the
/// broker by rest on these lists. A folder that is not there is the installation's to make.
fn check_program_parents(paths: &Paths) -> Result<(), Error> {
    let Some(parent) = paths.program.parent() else {
        return Ok(());
    };
    let mut chain: Vec<&Path> = parent
        .ancestors()
        .take_while(|folder| folder.starts_with(&paths.program_top))
        .collect();
    chain.reverse();
    for folder in chain {
        let wide = ffi::wide_path(folder);
        // SAFETY: the path is NUL-terminated; the call keeps nothing of it.
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        let handle = match ffi::Handle::new(raw, "opening a folder above the program directory") {
            Ok(handle) => handle,
            Err(failure)
                if failure.code == ERROR_FILE_NOT_FOUND || failure.code == ERROR_PATH_NOT_FOUND =>
            {
                return Ok(());
            }
            // Any other answer is not an absence: the folder could not be checked, and the person
            // is told what can be done about that.
            Err(failure) => {
                return Err(Error::Refused(format!(
                    "{} is a folder above the boundary's program directory (the program that the service runs as the system). It could not be opened to be checked ({failure}). Another program may hold it open, or its list may forbid the check: close that program, or correct who may open the folder, then run the setup program again. A change of its owner does not close a handle. Do not remove the program directory: the manifest records it and stays where it is.",
                    folder.display()
                )));
            }
        };
        let mut tag = FILE_ATTRIBUTE_TAG_INFO {
            FileAttributes: 0,
            ReparseTag: 0,
        };
        // SAFETY: the handle is open and the record is the size the class takes.
        if unsafe {
            GetFileInformationByHandleEx(
                handle.raw(),
                FileAttributeTagInfo,
                (&raw mut tag).cast(),
                size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
            )
        } == 0
        {
            return Err(ffi::last("reading a folder above the program directory").into());
        }
        let why = if tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
        {
            Some("it is a link or not a folder".to_owned())
        } else {
            let found = final_dos_path(&handle)?;
            if found.eq_ignore_ascii_case(&folder.display().to_string()) {
                acl::changeable_by_others_on(&handle, false)?
            } else {
                Some(format!("it is really {found}: a link leads there"))
            }
        };
        if let Some(why) = why {
            return Err(Error::Refused(format!(
                "{} is a folder above the boundary's program directory (the program that the service runs as the system). It is refused because {why}. Whoever owns it, or can add to it, rename or delete in it or change its list, could replace that program. Make the Administrators group, the system or the installer service its owner, leave only them able to change it, and if it is a link remove the link, then run the setup program again. Do not remove the program directory: the manifest records it and stays where it is.",
                folder.display()
            )));
        }
    }
    Ok(())
}

/// A folder's final path as the system gives it, without the `\\?\` prefix of its extended form.
fn final_dos_path(handle: &ffi::Handle) -> Result<String, Error> {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_NAME_NORMALIZED, GetFinalPathNameByHandleW, VOLUME_NAME_DOS,
    };
    let mut buffer = vec![0_u16; 512];
    loop {
        // SAFETY: the handle is open and the buffer length is passed.
        let length = unsafe {
            GetFinalPathNameByHandleW(
                handle.raw(),
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
            )
        };
        if length == 0 {
            return Err(ffi::last("reading a folder's final path").into());
        }
        if (length as usize) < buffer.len() {
            buffer.truncate(length as usize);
            break;
        }
        buffer.resize(length as usize + 1, 0);
    }
    let text = String::from_utf16_lossy(&buffer);
    Ok(text.strip_prefix(r"\\?\").unwrap_or(&text).to_owned())
}

/// Reads the program directory on a handle that is held, and everything in it on its own handle:
/// no link, one name for a file, the installation's own owner, and no right for another account to
/// change it. Nothing is done to the directory before this has passed. Returns whether the
/// directory was there to be opened and approved: a removal deletes the directory only when it was.
fn check_program_directory(paths: &Paths) -> Result<bool, Error> {
    check_program_parents(paths)?;
    if !paths.program.exists() {
        return Ok(false);
    }
    let program = paths.program.file_name().unwrap_or_default().to_owned();
    let held = match DirHandle::open_anchor_with(&paths.program, LIST | READ_CONTROL)? {
        Ok(held) => held,
        Err(refusal) => {
            // Only the volume is a refusal that no change of owner, list or open handle cures: a
            // link or a file at the program directory's name is removed.
            let cure = match refusal {
                AnchorRefusal::Volume(_) => Cure::Volume,
                AnchorRefusal::ReparsePoint | AnchorRefusal::NotADirectory => Cure::RemoveEntry,
            };
            return Err(within_refusal(
                paths,
                Scope::Program,
                paths.program.parent().unwrap_or(&paths.program),
                &program,
                &refusal.to_string(),
                cure,
            ));
        }
    };
    if let Some(why) = check_readable_object(held.handle())? {
        return Err(within_refusal(
            paths,
            Scope::Program,
            paths.program.parent().unwrap_or(&paths.program),
            &program,
            &why,
            Cure::OwnerAndList,
        ));
    }
    inspect_within(paths, Scope::Program, &paths.program, &held, 1)?;
    Ok(true)
}

/// Whether anything is at the path, a link that points nowhere and an entry that cannot be read
/// included. It is a look for a refusal's reason, and no deletion follows it.
fn entry_exists(path: &Path) -> bool {
    !matches!(fs::symlink_metadata(path), Err(error) if error.kind() == io::ErrorKind::NotFound)
}

/// The one name a proof directory holds: the unlisted program. Its bytes are those of the system's
/// own `hostname.exe`, so the file holds no secret; the proof makes it with a descriptor of its own
/// kind, which lets the one boundary account under proof read and run it and nobody else but the
/// system and the administrators have any right on it.
const PROOF_PROGRAM: &str = "unlisted.exe";

/// Reads what a proof directory holds: the unlisted program and nothing else, a file with one
/// name, on its own handle, owned as the installation's own and changeable by no other account.
fn inspect_proof_directory(paths: &Paths, dir: &Path, held: &DirHandle) -> Result<(), Error> {
    for child in held.children()? {
        let shown = OsString::from_wide(&child.name);
        if !shown.to_string_lossy().eq_ignore_ascii_case(PROOF_PROGRAM) {
            return Err(removal_refusal(
                paths,
                dir,
                &shown,
                "the installation puts nothing but the unlisted program in a proof directory",
            ));
        }
        let opened = match held.open_child(&child, READ_CONTROL)? {
            Ok(opened) => opened,
            Err(lost) => {
                return Err(removal_refusal(
                    paths,
                    dir,
                    &shown,
                    &format!("it could not be opened to be checked ({lost})"),
                ));
            }
        };
        match opened.kind {
            Kind::File if opened.links == 1 => {}
            Kind::File => {
                return Err(removal_refusal(
                    paths,
                    dir,
                    &shown,
                    "it has more than one name",
                ));
            }
            Kind::ReparsePoint => return Err(removal_refusal(paths, dir, &shown, "it is a link")),
            Kind::Directory => {
                return Err(removal_refusal(
                    paths,
                    dir,
                    &shown,
                    "it is a directory, not a file",
                ));
            }
        }
        if let Some(why) = check_readable_object(&opened.handle)? {
            return Err(removal_refusal(paths, dir, &shown, &why));
        }
    }
    Ok(())
}

/// The names of the private roots that a journal names as unfinished work, read as the removal
/// reads the journal.
fn roots_named_by_the_journal(paths: &Paths) -> Result<BTreeSet<String>, Error> {
    use crate::journal::rows::Row;
    let mut named = BTreeSet::new();
    if !paths.journal.exists() {
        return Ok(named);
    }
    let unfinished = super::journal::replay(&paths.journal, "")
        .map_err(|error| Error::Failed(format!("reading the journal: {error}")))?;
    for invocation in unfinished {
        for row in &invocation.rows {
            if let Row::RootIntent { name } | Row::RootMade { name, .. } = row {
                named.insert(name.as_str().to_owned());
            }
        }
    }
    Ok(named)
}

/// What the installation makes in the program directory under a name: the two programs are files;
/// the directory of Git's empty settings is a directory, and in it the configuration is a file and
/// the hooks and the template are directories that hold nothing. Any other name is none.
fn program_kind(paths: &Paths, dir: &Path, name: &str) -> Option<Kind> {
    let is = |given: &str| name.eq_ignore_ascii_case(given);
    if dir
        .as_os_str()
        .eq_ignore_ascii_case(paths.program.as_os_str())
    {
        let git = paths.git.file_name().map(|git| git.to_string_lossy());
        if is(BROKER) || is(CREDENTIAL) {
            Some(Kind::File)
        } else if git.is_some_and(|git| is(&git)) {
            Some(Kind::Directory)
        } else {
            None
        }
    } else if dir.as_os_str().eq_ignore_ascii_case(paths.git.as_os_str()) {
        if is(GIT_CONFIG) {
            Some(Kind::File)
        } else if is("hooks") || is("template") {
            Some(Kind::Directory)
        } else {
            None
        }
    } else {
        None
    }
}

/// Whether the entry is Git's global configuration that the broker points Git at, which the
/// installation makes empty and records with the digest of nothing.
fn is_git_config(paths: &Paths, dir: &Path, name: &str) -> bool {
    dir.as_os_str().eq_ignore_ascii_case(paths.git.as_os_str())
        && name.eq_ignore_ascii_case(GIT_CONFIG)
}

/// The size of an open file, read on its handle.
fn file_size(handle: &ffi::Handle) -> Result<u64, Error> {
    let mut size = 0_i64;
    // SAFETY: the handle is open with the right to read its attributes and the pointer is to a
    // local that lives through the call.
    if unsafe { GetFileSizeEx(handle.raw(), &raw mut size) } == 0 {
        return Err(Error::Failed(format!(
            "reading the size of a file: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(u64::try_from(size).unwrap_or(0))
}

/// Reads every entry below a directory of the staging layout, whatever its name, on its own
/// handle: no link, one name for a file, the installation's own owner, and no right for another
/// account to change it.
fn inspect_within(
    paths: &Paths,
    scope: Scope,
    dir: &Path,
    held: &DirHandle,
    depth: usize,
) -> Result<(), Error> {
    for child in held.children()? {
        let shown = OsString::from_wide(&child.name);
        if depth > WITHIN_DEPTH {
            return Err(within_refusal(
                paths,
                scope,
                dir,
                &shown,
                "it is nested deeper than the installation makes anything",
                Cure::RemoveEntry,
            ));
        }
        let opened = match held.open_child(&child, LIST | READ_CONTROL)? {
            Ok(opened) => opened,
            Err(lost) => {
                return Err(within_refusal(
                    paths,
                    scope,
                    dir,
                    &shown,
                    &format!("it could not be opened to be checked ({lost})"),
                    Cure::Open,
                ));
            }
        };
        if opened.kind == Kind::ReparsePoint {
            return Err(within_refusal(
                paths,
                scope,
                dir,
                &shown,
                "it is a link",
                Cure::RemoveEntry,
            ));
        }
        if opened.kind == Kind::File && opened.links > 1 {
            return Err(within_refusal(
                paths,
                scope,
                dir,
                &shown,
                "it has more than one name",
                Cure::RemoveEntry,
            ));
        }
        if matches!(scope, Scope::Program) {
            let name = shown.to_string_lossy();
            let reason = match program_kind(paths, dir, &name) {
                None => Some("the installation does not give that name there"),
                Some(Kind::File) if opened.kind != Kind::File => {
                    Some("it is a directory, not a file")
                }
                Some(Kind::Directory) if opened.kind != Kind::Directory => {
                    Some("it is a file, not a directory")
                }
                // The configuration is recorded with the digest of nothing, so what is there must
                // be nothing: a repair makes it again once it is removed.
                Some(_) if is_git_config(paths, dir, &name) && file_size(&opened.handle)? != 0 => {
                    Some("it holds settings, and the installation's own configuration is empty")
                }
                Some(_) => None,
            };
            if let Some(why) = reason {
                let cure = if is_git_config(paths, dir, &name) && opened.kind == Kind::File {
                    Cure::EmptyConfig
                } else {
                    Cure::RemoveEntry
                };
                return Err(within_refusal(paths, scope, dir, &shown, why, cure));
            }
        }
        if let Some(why) = check_readable_object(&opened.handle)? {
            return Err(within_refusal(
                paths,
                scope,
                dir,
                &shown,
                &why,
                Cure::OwnerAndList,
            ));
        }
        if opened.kind == Kind::Directory {
            let inner = DirHandle::from_opened(opened)?;
            inspect_within(paths, scope, &dir.join(&shown), &inner, depth + 1)?;
        }
    }
    Ok(())
}

/// Opens the data directory beneath the held folder without making it, checks it on its handle, and
/// reads what it holds. Returns none when the directory is not there.
fn inspect_existing_data(
    paths: &Paths,
    parent: &ffi::Handle,
) -> Result<Option<(DirHandle, Inspected)>, Error> {
    let name = paths
        .data
        .file_name()
        .ok_or_else(|| Error::Failed("the data directory has no name".to_owned()))?;
    let Some((handle, _)) =
        open_directory_relative(parent, name, FILE_OPEN, None, LIST | WRITE_DAC)
            .map_err(|error| data_failure(paths, error))?
    else {
        return Ok(None);
    };
    if let Some(why) = not_a_plain_directory(&handle, &paths.data.display().to_string())? {
        return Err(data_refusal(paths, why, &Origin::Foreign));
    }
    if let Some(why) = check_data_object(&handle).map_err(|error| data_failure(paths, error))? {
        return Err(data_refusal(paths, &why, &origin_of(&handle)));
    }
    let data = held_directory(handle)?;
    let inspected = inspect_data_directory(paths, &data)?;
    Ok(Some((data, inspected)))
}

/// Holds the folder above the data directory, made first when it is not there, and makes the data
/// directory beneath it, relative to the held folder, in one call that carries the directory's own
/// protected list, so that it is never there with the list it would take from the folder. The
/// folder is made in one call that carries its protected list, and is then opened and checked like
/// one that was there. A data directory that is already there is not trusted for being there: its
/// owner and its list are read on the handle that opened it and must be the installation's own, a
/// link is refused, and every entry in it must be one the installation made, each checked on its
/// own handle (its owner, every entry of its list, no link, one name for a file). The handles are returned, so the folder that passed
/// the check is the folder the data directory is made in, the directory that passed is the one
/// that is protected, and the directories in it that passed are the ones that are protected.
///
/// # Errors
///
/// Returns [`Error::Refused`] naming the reason when the folder, the directory or anything in it is
/// not the installation's own, and the platform's error when a call fails.
pub fn make_data_directory(paths: &Paths) -> Result<DataHolds, Error> {
    let held = match check_data_parent(paths)? {
        Some(held) => held,
        None => {
            create_data_parent(paths.data_parent())?;
            check_data_parent(paths)?.ok_or_else(|| {
                Error::Failed(format!(
                    "{} was made and is gone again",
                    paths.data_parent().display()
                ))
            })?
        }
    };
    let name = paths
        .data
        .file_name()
        .ok_or_else(|| Error::Failed("the data directory has no name".to_owned()))?;
    let descriptor = data_descriptor()?;
    // A directory that is there is opened, one that is not is made with the descriptor, and a link
    // is opened as the link and refused below.
    let (made, created) = open_directory_relative(
        &held,
        name,
        FILE_OPEN_IF,
        Some(&descriptor),
        LIST | WRITE_DAC,
    )?
    .ok_or_else(|| Error::Failed("the data directory was made and is gone again".to_owned()))?;
    if let Some(why) = not_a_plain_directory(&made, &paths.data.display().to_string())? {
        return Err(data_refusal(paths, why, &Origin::Foreign));
    }
    if let Some(why) = check_data_object(&made).map_err(|error| data_failure(paths, error))? {
        return Err(data_refusal(paths, &why, &origin_of(&made)));
    }
    let data = held_directory(made)?;
    let inspected = if created {
        Inspected {
            manifest: None,
            staging: None,
            journal: None,
            run: None,
        }
    } else {
        inspect_data_directory(paths, &data)?
    };
    Ok(DataHolds {
        paths: paths.clone(),
        _parent: held,
        data,
        staging: inspected.staging,
        journal: inspected.journal,
        run: inspected.run,
    })
}

/// Makes the folder above the data directory with the protected list, in one call.
fn create_data_parent(parent: &Path) -> Result<(), Error> {
    let descriptor = sd::descriptor(SdKind::DataParent, &Principals::default())?;
    let attributes = descriptor.attributes();
    let wide = ffi::wide_path(parent);
    // SAFETY: the path is NUL-terminated and the attributes point at a descriptor that lives
    // through the call.
    if unsafe { CreateDirectoryW(wide.as_ptr(), &raw const attributes) } == 0 {
        // SAFETY: reads the calling thread's last error.
        let code = unsafe { GetLastError() };
        // A folder that appeared between the look and this call is opened and checked next.
        if code != ERROR_ALREADY_EXISTS {
            return Err(Error::Failed(format!(
                "making {}: Windows error {code}",
                parent.display()
            )));
        }
    }
    Ok(())
}

/// Reads the state of every kind of application control and refuses when any is in force. Anything
/// that cannot be read refuses too.
fn refuse_when_controlled(channel: &Channel) -> Result<(String, Policy), Error> {
    let (xml, effective) = channel.effective()?;
    let ours: Vec<&str> = [
        policy::RULE_ALLOW_ALL,
        policy::RULE_CHECKOUT,
        policy::RULE_CONNECT,
    ]
    .into_iter()
    .filter(|id| {
        effective
            .collections
            .get(policy::EXE)
            .is_some_and(|collection| collection.rules.contains_key(*id))
    })
    .collect();
    if !ours.is_empty() {
        return Err(Error::Refused(format!(
            "application control already holds rule(s) of this installation's names: {}",
            ours.join(", ")
        )));
    }
    if !effective.is_unconfigured() {
        return Err(Error::Refused(
            "this computer already enforces application control, so the installation stops and changes nothing"
                .to_owned(),
        ));
    }
    refuse_software_restriction()?;
    refuse_smart_app_control()?;
    refuse_code_integrity()?;
    Ok((xml, effective))
}

fn refuse_software_restriction() -> Result<(), Error> {
    let Some(key) = registry::open(r"SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers")?
    else {
        return Ok(());
    };
    if key.dword("DefaultLevel")?.is_some() {
        return Err(Error::Refused(
            "a software restriction policy is set on this computer".to_owned(),
        ));
    }
    for level in key.subkey_names()? {
        if !level.chars().all(|character| character.is_ascii_digit()) {
            continue;
        }
        for kind in ["Paths", "Hashes", "UrlZones"] {
            if let Some(rules) = registry::open(&format!(
                r"SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\{level}\{kind}"
            ))? && !rules.subkey_names()?.is_empty()
            {
                return Err(Error::Refused(
                    "a software restriction policy holds rules on this computer".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn refuse_smart_app_control() -> Result<(), Error> {
    let state = registry::open(r"SYSTEM\CurrentControlSet\Control\CI\Policy")?
        .map(|key| key.dword("VerifiedAndReputablePolicyState"))
        .transpose()?
        .flatten();
    match state {
        Some(0) => Ok(()),
        Some(other) => Err(Error::Refused(format!(
            "Smart App Control is on or evaluating on this computer (state {other})"
        ))),
        None => Err(Error::Refused(
            "Smart App Control's state could not be read".to_owned(),
        )),
    }
}

fn refuse_code_integrity() -> Result<(), Error> {
    let listing = |error: &dyn std::fmt::Display| {
        Error::Refused(format!(
            "the code-integrity policies could not be listed: {error}"
        ))
    };
    let root = ffi::system_windows_directory().map_err(|error| listing(&error))?;
    let tool = Path::new(&root).join("System32").join("CiTool.exe");
    let output = applocker::trusted_command(&tool)
        .map_err(|error| listing(&error))?
        .args(["--list-policies", "--json"])
        .stdin(Stdio::null())
        .output()
        .map_err(|error| {
            Error::Refused(format!(
                "the code-integrity policies could not be listed: {error}"
            ))
        })?;
    if !output.status.success() {
        return Err(Error::Refused(format!(
            "the code-integrity policies could not be listed: {}",
            output.status
        )));
    }
    let listing: serde_json::Value = serde_json::from_slice(&output.stdout).map_err(|error| {
        Error::Refused(format!(
            "the code-integrity policies could not be read: {error}"
        ))
    })?;
    let policies = listing["Policies"].as_array().ok_or_else(|| {
        Error::Refused("the code-integrity policies could not be read".to_owned())
    })?;
    for entry in policies {
        let system = entry["IsSystemPolicy"].as_bool().unwrap_or(false);
        let enforced = entry["IsEnforced"].as_bool().unwrap_or(true);
        let name = entry["FriendlyName"].as_str().unwrap_or("");
        if !system {
            return Err(Error::Refused(format!(
                "a code-integrity policy beyond the system's is present: {name}"
            )));
        }
        if enforced && name.starts_with("VerifiedAndReputable") {
            return Err(Error::Refused("Smart App Control is enforcing".to_owned()));
        }
    }
    Ok(())
}

/// Finds Git where it installs for every account, refuses when anyone but the system's own class
/// could change it, and records what the policy will name. Git is started with an emptied
/// environment and the system's own working directory.
///
/// # Errors
///
/// Returns [`Error::Refused`] when Git is not where the policy expects it, can be changed by
/// others, or cannot be run.
pub fn qualify_git() -> Result<GitSet, Error> {
    let dir = git_dir()?;
    let mut images = Vec::new();
    for relative in policy::git_images() {
        let path = dir.join(relative);
        let bytes = fs::read(&path).map_err(|_| {
            Error::Refused(format!(
                "Git's program {} is not where the policy expects it",
                path.display()
            ))
        })?;
        if let Some(finding) = acl::changeable_by_others(&path, false)? {
            return Err(Error::Refused(format!(
                "{} can be changed by others: {finding}",
                path.display()
            )));
        }
        let mut ancestor = path.parent();
        while let Some(parent) = ancestor {
            if parent.parent().is_none() {
                break;
            }
            if let Some(finding) = acl::changeable_by_others(parent, true)? {
                return Err(Error::Refused(format!(
                    "{} can be replaced by others: {finding}",
                    parent.display()
                )));
            }
            ancestor = parent.parent();
        }
        images.push(Image {
            path: (*relative).to_owned(),
            sha256: hex::encode(Sha256::digest(&bytes)),
        });
    }
    let output = applocker::trusted_command(dir.join("mingw64").join("bin").join("git.exe"))
        .and_then(|mut command| command.arg("--version").stdin(Stdio::null()).output())
        .map_err(|error| Error::Refused(format!("Git could not be run: {error}")))?;
    // What Git reports is the version the policy is written for: a run that failed, or wrote
    // anything but its one line, is not Git.
    let version = git_version(output.status.success(), &output.stdout).ok_or_else(|| {
        Error::Refused(format!(
            "Git did not report its version: it ended with {} and wrote {:?}",
            output.status,
            String::from_utf8_lossy(&output.stdout).trim()
        ))
    })?;
    Ok(GitSet {
        dir: dir.display().to_string(),
        version,
        images,
    })
}

/// One payload file, staged and checked.
struct Staged {
    name: &'static str,
    path: PathBuf,
    sha256: String,
}

/// Copies each payload file into the staging directory through one open handle, checks its
/// signature there and records its digest.
fn stage_payload(payload: &Path, staging: &Path) -> Result<Vec<Staged>, Error> {
    let mut staged = Vec::new();
    for name in [BROKER, CREDENTIAL] {
        let source = payload.join(name);
        let metadata = fs::symlink_metadata(&source).map_err(|_| {
            Error::Refused(format!(
                "{} is not in the payload directory",
                source.display()
            ))
        })?;
        if metadata.file_type().is_symlink()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(Error::Refused(format!(
                "{} is a link, not a file",
                source.display()
            )));
        }
        let mut handle = OpenOptions::new()
            .read(true)
            .share_mode(0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&source)
            .map_err(io_error(format!("opening {}", source.display())))?;
        let mut bytes = Vec::new();
        handle
            .read_to_end(&mut bytes)
            .map_err(io_error(format!("reading {}", source.display())))?;
        drop(handle);
        let (mut made, path) = fresh::named_file(staging, "payload", ".exe", SdKind::AdminFile)
            .map_err(io_error(format!("staging {name}")))?;
        made.write_all(&bytes)
            .and_then(|()| made.sync_all())
            .map_err(io_error(format!("staging {}", path.display())))?;
        drop(made);
        let checked = OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&path)
            .map_err(io_error(format!("opening {}", path.display())))?;
        let subject = verify::signer(&checked, &path)?;
        if subject != verify::PUBLISHER {
            return Err(Error::Refused(format!(
                "{name} is signed by {subject}, not by {}",
                verify::PUBLISHER
            )));
        }
        drop(checked);
        staged.push(Staged {
            name,
            path,
            sha256: hex::encode(Sha256::digest(&bytes)),
        });
    }
    Ok(staged)
}

fn sha256_of(path: &Path) -> Result<String, Error> {
    let bytes = fs::read(path).map_err(io_error(format!("reading {}", path.display())))?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

/// The state of a run: where it works and what it has recorded.
struct Run {
    paths: Paths,
    manifest: Manifest,
}

impl Run {
    /// Records an object and writes the manifest, before the step that makes the object.
    fn record(&mut self, kind: ObjectKind, id: &str, detail: Option<&str>) -> Result<(), Error> {
        self.manifest.record(kind, id, detail);
        self.manifest.save(&self.paths.manifest)?;
        Ok(())
    }
}

/// The permission list of the service: the system and administrators in full, and each enrolled
/// person only to see whether the service runs and how it is set up.
fn service_security(persons: &[String]) -> String {
    let mut list =
        String::from("D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)");
    for person in persons {
        list.push_str(&format!("(A;;CCLCLORC;;;{person})"));
    }
    list
}

/// Records a failed step and goes on to the next, so that one failure does not leave the rest of
/// the removal undone.
fn keep(result: Result<(), Error>, what: &str, failures: &mut Vec<String>) {
    if let Err(error) = result {
        say(&format!("{what} failed: {error}"));
        failures.push(format!("{what}: {error}"));
    }
}

/// What `install` and `repair` are asked.
pub struct Options {
    /// The directory the setup program's signed payload is in.
    pub payload: PathBuf,
    /// The person the broker serves, as an identifier, or `None` for the account running setup.
    pub person: Option<String>,
}

/// Asks the person to type yes after showing the notice.
///
/// # Errors
///
/// Returns [`Error::Refused`] for any answer but yes.
pub fn confirm(person: &str, action: &str) -> Result<(), Error> {
    say(NOTICE);
    say("");
    say(&format!("The broker will serve the account {person}."));
    print!("Type yes to {action}: ");
    let _ = io::stdout().flush();
    let mut answer = String::new();
    io::stdin()
        .lock()
        .read_line(&mut answer)
        .map_err(io_error("reading the answer"))?;
    if answer.trim().eq_ignore_ascii_case("yes") {
        Ok(())
    } else {
        Err(Error::Refused(
            "the answer was not yes, so nothing was changed".to_owned(),
        ))
    }
}

fn person_of(options: &Options) -> Result<String, Error> {
    match &options.person {
        Some(text) => Ok(Sid::parse(text)?.to_text()),
        None => Ok(token::current_user()?.to_text()),
    }
}

/// Installs the boundary, or repairs an installation, and proves it in force.
///
/// # Errors
///
/// Returns the reason the installation stopped. When it stops after a change was made, the
/// removal sequence has run and the machine has been checked against the earlier-state record.
pub fn install(paths: &Paths, options: &Options, repair: bool) -> Result<(), Error> {
    if !token::current_is_administrator()? {
        return Err(Error::Refused(
            "run the setup program as an administrator".to_owned(),
        ));
    }
    let person = person_of(options)?;
    let state = entry(paths)?;
    let (manifest, existing) = match (state, repair) {
        (Entry::Fresh, false) => (Manifest::begin(), false),
        (Entry::Fresh, true) => {
            return Err(Error::Refused(
                "nothing is installed, so there is nothing to repair".to_owned(),
            ));
        }
        (Entry::Installed(_) | Entry::Partial(_), false) => {
            return Err(Error::Refused(
                "the boundary is already installed or half installed: use repair or remove"
                    .to_owned(),
            ));
        }
        (Entry::Installed(manifest) | Entry::Partial(manifest), true) => (manifest, true),
    };
    let mut run = Run {
        paths: paths.clone(),
        manifest,
    };
    if !run.manifest.persons.contains(&person) {
        run.manifest.persons.push(person);
    }
    let outcome = lay_down(&mut run, options, existing);
    if let Err(failure) = outcome {
        say(&format!("the installation stopped: {failure}"));
        if existing {
            return Err(failure);
        }
        say("undoing what was done");
        match remove(paths, true) {
            Ok(()) => say("the earlier state is back"),
            Err(error) => say(&format!(
                "the removal after the failure also failed: {error}"
            )),
        }
        return Err(failure);
    }
    Ok(())
}

fn lay_down(run: &mut Run, options: &Options, existing: bool) -> Result<(), Error> {
    let paths = run.paths.clone();
    // The folder, the directory and the directories in it are held, and each list goes on its own
    // handle, until everything beneath them is made and protected. A directory that is there was
    // checked on its handle, with every entry of the data directory, before this.
    let mut holds = make_data_directory(&paths)?;
    holds.protect()?;
    run.record(
        ObjectKind::Directory,
        &paths.data.display().to_string(),
        None,
    )?;
    // The staging directory, the journal and the parent of the private roots: administrators and
    // the system only, so no boundary token can list, create in or delete from any of them. Each is
    // recorded before it is made.
    for (which, what) in [
        (DataChild::Staging, "the staging directory"),
        (DataChild::Journal, "the journal directory"),
        (DataChild::Run, "the directory of the private roots"),
    ] {
        run.record(
            ObjectKind::Directory,
            &which.path(&paths).display().to_string(),
            None,
        )?;
        holds.directory(which).map_err(|error| match error {
            Error::Refused(_) => error,
            other => Error::Failed(format!("making {what}: {other}")),
        })?;
    }
    drop(holds);
    let channel = Channel::new(&paths.staging);
    // What an earlier run left in staging was checked as the layout names it; it is removed.
    let sweep = |staging: &Path| {
        if let Ok(entries) = fs::read_dir(staging) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                match layout_kind(Layout::Staging, &name) {
                    Some(Kind::Directory) => {
                        let _ = fs::remove_dir_all(entry.path());
                    }
                    Some(_) => {
                        let _ = fs::remove_file(entry.path());
                    }
                    None => {}
                }
            }
        }
    };
    sweep(&paths.staging);

    say("reading what is on this computer");
    let (baseline_xml, effective) = if existing {
        let (xml, effective) = channel.effective()?;
        let foreign = effective.foreign_exe_rules();
        if !foreign.is_empty() {
            return Err(Error::Refused(
                "an administrator has added a rule to the executable collection since the installation, so a repair would change what that rule means"
                    .to_owned(),
            ));
        }
        (xml, effective)
    } else {
        refuse_when_controlled(&channel)?
    };
    let _ = effective;
    let git = qualify_git()?;
    say(&format!("Git: {} at {}", git.version, git.dir));
    let staged = stage_payload(&options.payload, &paths.staging)?;
    for file in &staged {
        say(&format!(
            "{} verified: signed by {}, sha256 {}",
            file.name,
            verify::PUBLISHER,
            file.sha256
        ));
    }
    run.manifest.git = Some(git);
    run.manifest.save(&paths.manifest)?;

    let appid = service::manager()?.open(APPID)?.ok_or_else(|| {
        Error::Refused(
            "the Application Identity service does not exist on this computer".to_owned(),
        )
    })?;
    let (appid_start, _) = appid.configuration()?;
    let appid_running = appid.status()?.running();
    let prior = Prior {
        store: STORE_VERSION,
        appid_start_type: appid_start,
        appid_running,
        policy_xml: baseline_xml,
    };
    if prior.write_once(&paths.prior)? {
        say("the earlier state is recorded");
    }
    inject("directories")?;

    // The program directory and its files.
    let manager = service::manager()?;
    let broker_service = manager.open(SERVICE)?;
    if let Some(service) = &broker_service
        && service.status()?.running()
    {
        service.stop()?;
        service.wait_for(true, Duration::from_secs(60))?;
    }
    run.record(
        ObjectKind::Directory,
        &paths.program.display().to_string(),
        None,
    )?;
    // Every object of the program directory is made new with its descriptor in the call that makes
    // it (the Administrators group owns it whoever runs the installation, and no list is set by
    // path afterwards); one that an earlier run of this installation made was checked on its handle
    // before anything was done to it.
    let readable = Principals {
        users_may_read: true,
        ..Principals::default()
    };
    check_program_parents(&paths)?;
    fresh::directory_all(&paths.program, SdKind::AdminDir, &readable)
        .map_err(io_error("making the program directory"))?;
    // What the broker points Git's global file, hooks path and template directory at: empty, and
    // readable by every account, never writable by one.
    run.record(
        ObjectKind::Directory,
        &paths.git.display().to_string(),
        None,
    )?;
    made_if_missing(
        &paths.git,
        &readable,
        "making the directory of Git's empty settings",
    )?;
    for part in ["hooks", "template"] {
        made_if_missing(
            &paths.git.join(part),
            &readable,
            &format!("making the empty {part} directory"),
        )?;
    }
    let empty_config = paths.git.join(GIT_CONFIG);
    run.record(
        ObjectKind::File,
        &empty_config.display().to_string(),
        Some(&hex::encode(Sha256::digest(b""))),
    )?;
    if !empty_config.exists() {
        fresh::file_at(&empty_config, SdKind::ProgramFile, true)
            .map_err(io_error("making the empty global configuration"))?;
    }
    for file in &staged {
        let target = paths.program.join(file.name);
        run.record(
            ObjectKind::File,
            &target.display().to_string(),
            Some(&file.sha256),
        )?;
        install_program_file(&file.path, &target)
            .map_err(io_error(format!("installing {}", file.name)))?;
        if sha256_of(&target)? != file.sha256 {
            return Err(Error::Failed(format!(
                "{} changed while it was installed",
                file.name
            )));
        }
        let _ = fs::remove_file(&file.path);
    }

    inject("payload")?;

    // The accounts.
    let mut sids = Vec::new();
    for name in [CHECKOUT, CONNECT] {
        let sid = match account::find(name) {
            Some(sid) if existing => sid,
            _ => {
                run.record(ObjectKind::Account, name, None)?;
                account::create(name)?
            }
        };
        run.record(ObjectKind::Account, name, Some(&sid.to_text()))?;
        run.record(ObjectKind::Right, &format!("{name}:deny-sign-in"), None)?;
        account::grant_rights(&sid, &account::DENY_RIGHTS)?;
        run.record(
            ObjectKind::RegistryValue,
            &format!("SpecialAccounts\\{name}"),
            None,
        )?;
        account::hide_from_sign_in(name)?;
        say(&format!(
            "account {name} ({}) refused sign-in and hidden from the sign-in screen",
            sid.to_text()
        ));
        sids.push(sid);
    }

    inject("accounts")?;

    // The service.
    run.record(ObjectKind::Service, SERVICE, None)?;
    let broker_service = match manager.open(SERVICE)? {
        Some(service) => service,
        None => manager.create(
            SERVICE,
            DISPLAY,
            &paths.program.join(BROKER).display().to_string(),
        )?,
    };
    broker_service.configure(
        "Starts Git for KalaReach as its two repository boundary accounts, on behalf of the people it serves.",
        &BROKER_PRIVILEGES,
    )?;
    broker_service.set_security(&service_security(&run.manifest.persons))?;
    run.manifest.save(&paths.manifest)?;

    inject("service")?;

    // The Application Identity service first. A policy written before the service has applied one is
    // not enforced, and the service applies its first about two minutes after it starts.
    run.record(
        ObjectKind::AppIdentity,
        APPID,
        Some(&format!("start={AUTOMATIC}")),
    )?;
    if appid_start != AUTOMATIC {
        Identity(&appid).set_automatic()?;
    }
    let git = run
        .manifest
        .git
        .clone()
        .ok_or_else(|| Error::Failed("no Git installation is recorded".to_owned()))?;
    let log_env = proof::proof_environment(&git, &paths.staging).map_err(Error::Failed)?;
    // A service that is already running is never stopped. An event of an earlier life of the service
    // says nothing about what it has applied now, so none is trusted: the policy is written and the
    // next event after that write is waited for, for as long as a first event may take. A service
    // that this installation starts is waited for first, because a policy written before it has
    // applied one is not enforced.
    let was_running = appid.status()?.running();
    if was_running {
        inject("appid")?;
        say(
            "the Application Identity service is already running, so the policy is written and the platform's report of it is awaited",
        );
    } else {
        let before_start = applocker::newest_record(&paths.staging, &log_env, within(QUERY_BOUND))?;
        Identity(&appid).start()?;
        let first_deadline = within(FIRST_APPLIED_BOUND);
        inject("appid")?;
        say(messages::APPLICATION_CONTROL_STARTING);
        let (waited, _) = wait_for_applied(
            before_start,
            first_deadline,
            "the Application Identity service's first \"policy applied\" event",
            &paths.staging,
            &log_env,
        )?;
        say(&format!(
            "application control has started, {:.0} s after the service",
            waited.as_secs_f32()
        ));
    }

    // The policy, and the platform's next event that says it applied it.
    let wanted = Policy::installed(&sids[0].to_text(), &sids[1].to_text());
    for id in [
        policy::RULE_ALLOW_ALL,
        policy::RULE_CHECKOUT,
        policy::RULE_CONNECT,
    ] {
        run.record(ObjectKind::PolicyRule, id, None)?;
    }
    // The log's newest record is read by the process that writes the policy, right before it writes,
    // and comes back with the write's answer: an event after that number came after the write began.
    let before_write = channel.set(&wanted.render())?;
    note_call(&format!("policy written after record {before_write}"));
    say("the policy is written");
    inject("policy")?;
    let (_, applied_record) = wait_for_applied(
        before_write,
        within(if was_running {
            FIRST_APPLIED_BOUND
        } else {
            NEXT_APPLIED_BOUND
        }),
        "the \"policy applied\" event after the policy was written",
        &paths.staging,
        &log_env,
    )?;
    note_call(&format!("policy applied by record {applied_record}"));
    say("the platform has applied the policy");
    let (after_xml, after) = channel.effective()?;
    let _ = after_xml;
    let differences = after.differences(&wanted);
    if !differences.is_empty() {
        return Err(Error::Failed(format!(
            "the platform reports a different policy from the one written: {}",
            differences.join("; ")
        )));
    }

    // The broker, and the proof through it: the start-up cycle's proofs, asked inside the cycle that
    // the broker opens when it starts.
    let cycle = ProofCycle::begin(PROOF_BOUND, PROOF_ASK_MARGIN, || {
        broker_service.start()?;
        Ok(broker_service.wait_for(false, Duration::from_secs(60))?)
    })?;
    say("the broker is running");
    inject("broker")?;
    let mut session = open_session()?;
    cycle.prove(&mut session)?;
    run.manifest.state = InstallState::Installed;
    run.manifest.save(&paths.manifest)?;
    say("the boundary is installed and in force");
    Ok(())
}

/// How long before the end of the start-up cycle the installation stops asking for a proof: a proof
/// asked later has too little time left to be answered inside the cycle.
const PROOF_ASK_MARGIN: Duration = Duration::from_secs(10);

/// The start-up proof's cycle as the installation counts it.
///
/// The broker opens its first cycle of proofs when it starts and ends it [`PROOF_BOUND`] later; a
/// proof asked after it begins a cycle of its own, and an answer from that cycle is not the answer
/// to anything the installation asked inside the first. The frame carries no cycle, so the
/// installation keeps to the first by its clock: it takes its instant before it starts the broker's
/// service, so its deadline is earlier than the broker's by at least the time the service takes to
/// start; it asks only before the deadline less a margin; and it reads every answer only until the
/// deadline and takes none that comes after it. An answer that was read before the installation's
/// deadline was written before the broker's, so it belongs to the first cycle.
pub struct ProofCycle {
    began: Instant,
    bound: Duration,
    margin: Duration,
}

impl ProofCycle {
    /// Takes the instant, then runs `start`, which starts the broker's service and waits until it
    /// runs. The instant is taken here and not after, so that it cannot come later than the
    /// broker's.
    ///
    /// # Errors
    ///
    /// Returns the error of `start`.
    pub fn begin(
        bound: Duration,
        margin: Duration,
        start: impl FnOnce() -> Result<(), Error>,
    ) -> Result<ProofCycle, Error> {
        let began = Instant::now();
        start()?;
        Ok(ProofCycle {
            began,
            bound,
            margin,
        })
    }

    /// When the installation's cycle ends: no answer is read after it.
    #[must_use]
    pub fn deadline(&self) -> Instant {
        self.began + self.bound
    }

    /// Asks the broker for the proof of each class, in the first cycle only.
    ///
    /// # Errors
    ///
    /// Returns an error when less than the margin is left before a request, when an answer does not
    /// come by the deadline, and when the broker says a proof failed.
    pub fn prove(&self, session: &mut pipe::Connection) -> Result<(), Error> {
        let deadline = self.deadline();
        let ask_until = deadline.checked_sub(self.margin).unwrap_or(self.began);
        for class in [Class::Checkout, Class::Connect] {
            if Instant::now() >= ask_until {
                return Err(Error::Failed(format!(
                    "the start-up proof's cycle of {} seconds had less than {} seconds left before the proof for {class:?} was asked",
                    self.bound.as_secs(),
                    self.margin.as_secs()
                )));
            }
            session.set_deadline(Some(deadline));
            let response = ask(session, &Request::Prove { class })?;
            if Instant::now() > deadline {
                return Err(Error::Failed(format!(
                    "the broker answered the proof for {class:?} after the end of its cycle of {} seconds",
                    self.bound.as_secs()
                )));
            }
            match response {
                Response::Proof {
                    ready: true,
                    detail,
                } => say(&detail),
                Response::Proof {
                    ready: false,
                    detail,
                } => {
                    return Err(Error::Failed(format!("the proof failed: {detail}")));
                }
                other => {
                    return Err(Error::Failed(format!(
                        "the broker answered a proof with {other:?}"
                    )));
                }
            }
        }
        Ok(())
    }
}

/// How long the installation waits for the platform's first "policy applied" event after it starts
/// the Application Identity service: the service applies its first policy about two minutes after
/// it starts. The same bound holds for the event after the policy's write when the service was
/// already running, since it may be in its first minutes.
const FIRST_APPLIED_BOUND: Duration = Duration::from_secs(300);
/// How long it waits for the next such event after it has written the policy: the platform applied
/// the policy within a second of the write in every run of the guest.
const NEXT_APPLIED_BOUND: Duration = Duration::from_secs(60);

/// The most one query of the application-control log may take.
const QUERY_BOUND: Duration = Duration::from_secs(60);
/// How long the broker may take to answer a hello.
const HELLO_BOUND: Duration = Duration::from_secs(30);

/// The time `bound` from now.
fn within(bound: Duration) -> Instant {
    Instant::now() + bound
}

/// Waits for the platform's "policy applied" event after a record number, and returns how long it
/// took and the event's record number. Every query of the log stays within the deadline, and an
/// event that was in hand only after the deadline is not taken as a success.
fn wait_for_applied(
    after: u64,
    deadline: Instant,
    what: &str,
    scratch: &Path,
    env: &crate::env::EnvBlock,
) -> Result<(Duration, u64), Error> {
    let begun = Instant::now();
    let too_late = || {
        Error::Failed(format!(
            "Windows did not report {what} within {} seconds",
            deadline.saturating_duration_since(begun).as_secs()
        ))
    };
    loop {
        let seen = applocker::policy_applied_after(after, scratch, env, deadline)?;
        if Instant::now() > deadline {
            return Err(too_late());
        }
        if let Some(record) = seen {
            return Ok((begun.elapsed(), record));
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(too_late());
        }
        std::thread::sleep(Duration::from_secs(1).min(left));
    }
}

/// Connects to the broker's pipe, checking that the process serving it is the service's.
///
/// # Errors
///
/// Returns an error when the service is not running, the pipe is served by another process, or the
/// versions differ.
pub fn open_session() -> Result<pipe::Connection, Error> {
    let manager = service::manager()?;
    let service = manager
        .open(SERVICE)?
        .ok_or_else(|| Error::Failed("the broker's service does not exist".to_owned()))?;
    let status = service.status()?;
    if !status.running() {
        return Err(Error::Failed(
            "the broker's service is not running".to_owned(),
        ));
    }
    let mut connection = pipe::connect(status.pid)?;
    connection.set_deadline(Some(Instant::now() + HELLO_BOUND));
    let said = ask(
        &mut connection,
        &Request::Hello {
            version: frame::VERSION,
        },
    )?;
    match said {
        Response::Hello { .. } => {
            // The caller sets the deadline of what it asks next.
            connection.set_deadline(None);
            Ok(connection)
        }
        other => Err(Error::Failed(format!(
            "the broker answered hello with {other:?}"
        ))),
    }
}

/// Sends one request and reads the answer, within the connection's deadline when it has one.
///
/// # Errors
///
/// Returns an error when the connection fails or the deadline passes before the answer.
pub fn ask(connection: &mut pipe::Connection, request: &Request) -> Result<Response, Error> {
    frame::write(connection, request).map_err(|error| Error::Failed(error.to_string()))?;
    frame::read(connection).map_err(|error| Error::Failed(error.to_string()))
}

/// Removes the installation and checks the computer against the earlier-state record.
///
/// With `quiet_when_empty`, an installation that has nothing recorded is not an error. The broker
/// is left in a maintenance state first, the policy is put back, the release is proved through the
/// broker, and only then is the broker, with the accounts and the files, taken away.
///
/// # Errors
///
/// Returns the reason a step failed, after trying every later step it could.
pub fn remove(paths: &Paths, quiet_when_empty: bool) -> Result<(), Error> {
    if !token::current_is_administrator()? {
        return Err(Error::Refused(
            "run the setup program as an administrator".to_owned(),
        ));
    }
    // The data directory is opened by handle, checked and read here, in this run, and the removal
    // acts on it and on what it holds only through what this inspection approved: a path that no
    // check opened is never read for a manifest and never deleted from. The handles are closed
    // before anything is deleted.
    let found = match check_data_parent(paths)? {
        Some(parent) => match inspect_existing_data(paths, &parent)? {
            Some((_, inspected)) => match inspected.manifest {
                Some(manifest) => records::Inspection::Recorded(manifest),
                None => records::Inspection::Empty,
            },
            None => records::Inspection::Absent,
        },
        None => records::Inspection::Absent,
    };
    #[cfg(feature = "testing")]
    testing::after_the_removal_inspection();
    // The program directory is read on a held handle before the removal deletes anything in it.
    let program_checked = check_program_directory(paths)?;
    if matches!(found, records::Inspection::Recorded(_)) {
        refuse_while_unfinished(paths)?;
    }
    let manifest = match records::begin(
        found,
        &|| entry_exists(&paths.data),
        quiet_when_empty,
        &paths.data,
    ) {
        records::Begin::Refuse(text) => return Err(Error::Refused(text)),
        records::Begin::Nothing => return Ok(()),
        records::Begin::FinishEmpty => {
            // What an earlier removal left when it was stopped between the manifest's deletion and
            // the directory's, or when the directory could not be deleted. It is the
            // installation's own, and the removal finishes it, also when nothing else is recorded.
            let stayed = records::remove_empty(&paths.data);
            if stayed.is_empty() {
                if let Some(parent) = paths.data.parent() {
                    let _ = fs::remove_dir(parent);
                }
                say("the empty data directory that an earlier removal left is removed");
                return Ok(());
            }
            return Err(Error::Failed(format!(
                "the data directory stays because {} could not be removed. {}",
                stayed.join("; "),
                records::next_step(false, data_is_empty(paths))
            )));
        }
        records::Begin::Remove(manifest) => manifest,
    };
    let prior = Prior::load(&paths.prior).ok();
    // A removal that took `staging` and could not delete the manifest leaves a manifest with no
    // `staging`, and the channel makes its temporary directory there: it is made again, empty, and
    // goes with the records.
    made_if_missing(
        &paths.staging,
        &Principals::default(),
        "making the staging directory again",
    )?;
    let channel = Channel::new(&paths.staging);
    let manager = service::manager()?;
    let mut failures: Vec<String> = Vec::new();
    // (1) the broker stays up and refuses new invocations.
    let mut session = None;
    if manifest.find(ObjectKind::Service, SERVICE).is_some()
        && let Some(service) = manager.open(SERVICE)?
    {
        if !service.status()?.running() {
            let _ = service.start();
            let _ = service.wait_for(false, Duration::from_secs(60));
        }
        match open_session().and_then(|mut connection| {
            ask(&mut connection, &Request::Maintenance { on: true })?;
            Ok(connection)
        }) {
            Ok(connection) => {
                say("the broker is in its maintenance state");
                session = Some(connection);
            }
            Err(error) => say(&format!(
                "the broker could not be reached, so the release will be read from the policy alone: {error}"
            )),
        }
    }

    // (2) the policy: our rules go; an administrator's rule keeps the allow-all rule beside it.
    let has_rules = manifest.of_kind(ObjectKind::PolicyRule).next().is_some();
    if has_rules {
        keep(
            (|| -> Result<(), Error> {
                let (xml, effective) = channel.effective()?;
                let (_, kept) = effective.without_ours();
                if kept {
                    say(
                        "an administrator's rule shares the executable collection, so the allow-all rule and the collection's mode stay in force beside it",
                    );
                }
                let drop: &[&str] = if kept {
                    &[policy::RULE_CHECKOUT, policy::RULE_CONNECT]
                } else {
                    &[
                        policy::RULE_ALLOW_ALL,
                        policy::RULE_CHECKOUT,
                        policy::RULE_CONNECT,
                    ]
                };
                channel.set(
                    &policy::strip(&xml, drop).map_err(|error| Error::Failed(error.to_string()))?,
                )?;
                say("the policy is put back");
                Ok(())
            })(),
            "putting the policy back",
            &mut failures,
        );
    }

    // (3) the Application Identity service's start type goes back only where it is still ours.
    if let (Some(object), Some(prior)) = (manifest.find(ObjectKind::AppIdentity, APPID), &prior) {
        keep(
            (|| -> Result<(), Error> {
                let appid = manager.open(APPID)?.ok_or_else(|| {
                    Error::Failed("the Application Identity service is missing".to_owned())
                })?;
                let (current, _) = appid.configuration()?;
                let set_by_us = object.detail.as_deref() == Some(&format!("start={current}"));
                if set_by_us && current != prior.appid_start_type {
                    if let Some(key) = registry::open(APPID_KEY)? {
                        key.set_dword("Start", prior.appid_start_type)?;
                        say(&format!(
                            "the Application Identity service's start type is back to {}",
                            prior.appid_start_type
                        ));
                    }
                } else {
                    say(
                        "the Application Identity service's start type was changed by someone else and is left alone",
                    );
                }
                Ok(())
            })(),
            "restoring the Application Identity service's start type",
            &mut failures,
        );
    }

    // (4) the release, proved through the broker.
    if let Some(connection) = session.as_mut() {
        for class in [Class::Checkout, Class::Connect] {
            match ask(connection, &Request::Release { class }) {
                Ok(Response::Proof {
                    ready: true,
                    detail,
                }) => say(&detail),
                Ok(Response::Proof {
                    ready: false,
                    detail,
                }) => {
                    keep(
                        Err(Error::Failed(detail)),
                        "proving the release",
                        &mut failures,
                    );
                }
                Ok(other) => keep(
                    Err(Error::Failed(format!("{other:?}"))),
                    "proving the release",
                    &mut failures,
                ),
                Err(error) => keep(Err(error), "proving the release", &mut failures),
            }
        }
    }
    drop(session);

    // (5) the Application Identity service stops if the installation started it and no rule is left,
    // and the broker's service goes.
    if let Some(prior) = &prior {
        keep(
            (|| -> Result<(), Error> {
                let (_, effective) = channel.effective()?;
                let no_rules = effective
                    .collections
                    .values()
                    .all(|collection| collection.rules.is_empty());
                if !prior.appid_running
                    && no_rules
                    && let Some(appid) = manager.open(APPID)?
                    && appid.status()?.running()
                {
                    Identity(&appid).stop()?;
                    say("the Application Identity service is stopped as it was");
                }
                Ok(())
            })(),
            "stopping the Application Identity service",
            &mut failures,
        );
    }
    keep(
        (|| -> Result<(), Error> {
            if let Some(service) = manager.open(SERVICE)? {
                if service.status()?.running() {
                    service.stop()?;
                    service.wait_for(true, Duration::from_secs(60))?;
                }
                // The marker is a volatile key under the service's own key: it goes first.
                boot::remove()?;
                if service.marked_for_deletion()? {
                    say(
                        "the broker's service is already deleted and goes when the last program that holds it lets go",
                    );
                } else {
                    service.delete()?;
                    say("the broker's service is deleted");
                }
            }
            Ok(())
        })(),
        "deleting the broker's service",
        &mut failures,
    );

    // (6) the accounts, their rights and the files.
    for object in manifest.of_kind(ObjectKind::Account) {
        let name = object.id.clone();
        keep(
            (|| -> Result<(), Error> {
                if let Some(sid) = account::find(&name) {
                    account::revoke_all_rights(&sid)?;
                    account::delete_profile(&sid)?;
                }
                account::unhide_from_sign_in(&name)?;
                account::delete(&name)?;
                say(&format!("account {name} is removed with its rights"));
                Ok(())
            })(),
            "removing an account",
            &mut failures,
        );
    }
    if program_checked {
        keep(
            fs::remove_dir_all(&paths.program).map_err(io_error("removing the program directory")),
            "removing the program directory",
            &mut failures,
        );
        if let Some(parent) = paths.program.parent() {
            let _ = fs::remove_dir(parent);
        }
    } else if entry_exists(&paths.program) {
        // It was not there when the removal checked, so no check opened it: nothing is deleted.
        failures.push(format!(
            "{} was not there when the removal looked for it, and something is there now, so it was not removed",
            paths.program.display()
        ));
    }
    // The journal and the private roots' parent go only when empty. Unfinished work was refused
    // before the removal began; what a journal file still holds now is finished or made nothing.
    if let Ok(entries) = fs::read_dir(&paths.journal) {
        for entry in entries.flatten() {
            if entry.path().extension().and_then(|text| text.to_str()) == Some("journal") {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
    for directory in [&paths.run, &paths.journal] {
        if directory.exists() {
            keep(
                fs::remove_dir(directory).map_err(io_error(format!(
                    "removing {}, which still holds an unfinished invocation",
                    directory.display()
                ))),
                "removing the journal or the private roots",
                &mut failures,
            );
        }
    }
    if let Some(prior) = &prior {
        match residue(prior, paths) {
            Ok(left) if left.is_empty() => say("the machine matches the earlier-state record"),
            Ok(left) => {
                for line in &left {
                    say(&format!("not put back: {line}"));
                }
                failures.push(format!(
                    "the earlier state is not back: {}",
                    left.join("; ")
                ));
            }
            Err(error) => failures.push(format!("checking the earlier state: {error}")),
        }
    }
    if failures.is_empty() {
        // The records go last: a failed removal can be run again from them.
        let stayed = remove_records(paths);
        if stayed.is_empty() {
            say("the installation is removed");
            Ok(())
        } else {
            // While the manifest stays, the removal runs again whole and reads it. Without it,
            // an empty directory is finished by the next removal, and anything else in it is for
            // the person to remove.
            let next = records::next_step(paths.manifest.exists(), data_is_empty(paths));
            Err(Error::Failed(format!(
                "the service, the accounts and the policy are removed, but the data directory stays because {} could not be removed. {next}",
                stayed.join("; ")
            )))
        }
    } else {
        Err(Error::Failed(format!(
            "the removal did not finish and its records are kept: {}",
            failures.join("; ")
        )))
    }
}

/// Whether the data directory holds nothing.
fn data_is_empty(paths: &Paths) -> bool {
    fs::read_dir(&paths.data).is_ok_and(|mut entries| entries.next().is_none())
}

/// Removes the installation's own records, last of all, and then the data directory and, when it is
/// empty, the folder above it. The records go in the order [`records::remove`] gives: the manifest
/// last, so that a removal that stayed anywhere is run again from it. Returns each thing that could
/// not be removed, with the reason; nothing is returned when everything is gone.
pub fn remove_records(paths: &Paths) -> Vec<String> {
    let stayed = records::remove(&Records {
        data: &paths.data,
        manifest: &paths.manifest,
        prior: &paths.prior,
        staging: &paths.staging,
    });
    if let Some(parent) = paths.data.parent() {
        let _ = fs::remove_dir(parent);
    }
    stayed
}

/// Reads the journal and the directory of the private roots and refuses, before anything is
/// changed, while one holds work that is not done: an invocation that did not finish, one that
/// finished with a leftover, one whose file cannot be read, or a private root that is still there.
/// The journal holds the only saved lists of an unfinished release, so nothing that could end the
/// broker, take away its accounts or delete a file goes first.
///
/// # Errors
///
/// Returns [`Error::Refused`] naming the projects and roots, or the failure of the call that read.
pub fn refuse_while_unfinished(paths: &Paths) -> Result<(), Error> {
    use crate::journal::rows::Row;
    let mut found = Vec::new();
    match fs::read_dir(&paths.run) {
        Ok(entries) => {
            for entry in entries {
                let entry =
                    entry.map_err(io_error("reading the directory of the private roots"))?;
                found.push(format!(
                    "a private root {}",
                    entry.file_name().to_string_lossy()
                ));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(io_error("reading the directory of the private roots")(
                error,
            ));
        }
    }
    if paths.journal.exists() {
        let unfinished = super::journal::replay(&paths.journal, "")
            .map_err(|error| Error::Failed(format!("reading the journal: {error}")))?;
        for invocation in unfinished {
            let project = invocation
                .rows
                .iter()
                .find_map(|row| match row {
                    Row::Begin { tree_path, .. } => Some(tree_path.clone()),
                    _ => None,
                })
                .unwrap_or_else(|| "a project that is not named".to_owned());
            found.push(format!(
                "the invocation {} on {project} ({:?})",
                invocation.id, invocation.standing
            ));
        }
    }
    if found.is_empty() {
        Ok(())
    } else {
        Err(Error::Refused(format!(
            "unfinished work is recorded, so nothing was changed: {}",
            found.join("; ")
        )))
    }
}

/// What the installation changed that has not been put back, read from the machine against the
/// earlier-state record. An empty list means the baseline holds. The data directory is not
/// counted: it holds the records this check reads, and goes last.
///
/// # Errors
///
/// Returns the failure of a call that could not look.
pub fn residue(prior: &Prior, paths: &Paths) -> Result<Vec<String>, Error> {
    let mut left = Vec::new();
    let (_, effective) = Channel::new(&paths.staging).effective()?;
    let baseline =
        Policy::parse(&prior.policy_xml).map_err(|error| Error::Failed(error.to_string()))?;
    // Where an administrator's rule has since joined the executable collection, the removal keeps the
    // allow-all rule and the collection's mode beside it on purpose; everything else of ours is gone.
    let expected = if effective.foreign_exe_rules().is_empty() {
        baseline
    } else {
        effective.without_ours().0
    };
    left.extend(effective.differences(&expected));
    for name in [CHECKOUT, CONNECT] {
        if account::find(name).is_some() {
            left.push(format!("the account {name} is still there"));
        }
        if account::hidden_from_sign_in(name)? {
            left.push(format!("{name} is still hidden from the sign-in screen"));
        }
    }
    if let Some(service) = service::manager()?.open(SERVICE)?
        && !service.marked_for_deletion()?
    {
        left.push("the broker's service is still there".to_owned());
    }
    if paths.program.exists() {
        left.push(format!("{} is still there", paths.program.display()));
    }
    Ok(left)
}
