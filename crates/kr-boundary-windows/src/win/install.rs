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
use crate::remedy::{self, EntryKind, Origin, ParentCure, Presence, Purpose, Shape, Taken};

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_FOR_BACKUP_INTENT, FILE_OPEN_IF,
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
    CreateFileW, DELETE, FILE_ADD_SUBDIRECTORY, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_TAG_INFO,
    FILE_CASE_SENSITIVE_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_ID_128, FILE_ID_INFO,
    FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FileAttributeTagInfo, FileCaseSensitiveInfo, FileIdInfo,
    GetFileInformationByHandleEx, GetFileSizeEx, GetVolumeInformationByHandleW, OPEN_EXISTING,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
use windows_sys::Win32::System::SystemServices::FILE_CASE_SENSITIVE_SEARCH;

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
    // text: install_error-1
    #[error("{0}")]
    Refused(String),
    /// A call into the platform failed.
    // text: install_error-2
    #[error(transparent)]
    Win(#[from] ffi::Error),
    /// A known folder of the system could not be read.
    // text: install_error-3
    #[error(transparent)]
    KnownFolder(#[from] ffi::KnownFolderError),
    /// A record could not be read or written.
    // text: install_error-4
    #[error(transparent)]
    Store(#[from] StoreError),
    /// Application control could not be read or written.
    // text: install_error-5
    #[error(transparent)]
    Applocker(#[from] applocker::Error),
    /// A file operation failed.
    // text: install_error-6
    #[error("{what}: {source}")]
    Io {
        /// What was being done.
        what: String,
        /// The reason.
        source: io::Error,
    },
    /// A step failed in a way that is not one of the above.
    // text: install_error-7
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
        // text: inject-1
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
    use std::sync::Mutex;

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
        *crate::win::ffi::locked(&RAN_AFTER) = None;
        *crate::win::ffi::locked(&AFTER_A_READ) = Some(Box::new(hook));
    }

    /// The read the function ran after (`run` for the listing of the roots, `journal` for the read
    /// of the journal), or none while it has not run.
    pub fn listing_the_function_ran_after() -> Option<&'static str> {
        *crate::win::ffi::locked(&RAN_AFTER)
    }

    static AFTER_THE_INSPECTION: Mutex<Option<Hook>> = Mutex::new(None);

    /// Runs the function once, right after the removal has inspected the data directory and before
    /// it decides what to do: a directory that something made after the inspection found none
    /// there is then there, as it is on a machine where an ordinary account made it in between.
    pub fn after_the_removal_inspects_the_data_directory(hook: impl FnOnce() + Send + 'static) {
        *crate::win::ffi::locked(&AFTER_THE_INSPECTION) = Some(Box::new(hook));
    }

    /// Drops a function that was set and did not run, so that it does not run in another case.
    pub fn no_hook_after_the_removal_inspects_the_data_directory() {
        *crate::win::ffi::locked(&AFTER_THE_INSPECTION) = None;
    }

    pub(super) fn after_the_removal_inspection() {
        let hook = crate::win::ffi::locked(&AFTER_THE_INSPECTION).take();
        if let Some(hook) = hook {
            hook();
        }
    }

    pub(super) fn after_a_read(read: &'static str) {
        let hook = crate::win::ffi::locked(&AFTER_A_READ).take();
        if let Some(hook) = hook {
            hook();
            *crate::win::ffi::locked(&RAN_AFTER) = Some(read);
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
    // text: print_say-1
    println!("{line}");
}

/// Finds what state the computer is in, and refuses when an object of the installation's names
/// exists that the manifest does not list.
///
/// # Errors
///
/// Returns [`Error::Refused`] naming the foreign object, or the failure of the call that looked.
pub fn entry(paths: &Paths) -> Result<Entry, Error> {
    entered(paths, Purpose::Install)
}

/// [`entry`] for a status report: it reads what an installation reads and refuses the same objects,
/// but its refusals never tell the administrator to move, rename or remove anything, since a status
/// report is no installation.
///
/// # Errors
///
/// Returns [`Error::Refused`] naming the foreign object, or the failure of the call that looked.
pub fn status(paths: &Paths) -> Result<Entry, Error> {
    entered(paths, Purpose::Status)
}

/// [`entry`] for a run with this purpose. A refusal of an object on the way to the installation's
/// records tells the administrator to move, rename or remove it only at an installation, and only
/// after reads that succeeded found nothing of the installation (see [`remedy::Grounds`]).
fn entered(paths: &Paths, purpose: Purpose) -> Result<Entry, Error> {
    check_shape(paths, remedy::Stage::Before)?;
    // What the data directory holds is read on handles before any of it is used: the manifest
    // decides what a repair or a removal touches, so it is read only after the directory it is in
    // and everything beside it passed their checks.
    let inspected = match check_data_parent(paths)? {
        Some(parent) => {
            inspect_existing_data(paths, &parent, purpose)?.map(|(_, inspected)| inspected)
        }
        None => None,
    };
    // A data directory that passed its inspection is the installation's own: with no manifest it is
    // an empty one, which a new installation takes as it is.
    let data_accepted = inspected.is_some();
    if let Some(manifest) = inspected.and_then(|inspected| inspected.manifest) {
        check_program_directory(paths, true, remedy::Stage::Before)?;
        return Ok(match manifest.state {
            InstallState::Installed => Entry::Installed(manifest),
            InstallState::InProgress => Entry::Partial(manifest),
        });
    }
    // The folders above the program tree are read here, before anything is made, written or
    // stopped, as the folders above the data tree were by the check above; a link at the program
    // directory's name, one that points nowhere included, gets the link's own remedy.
    check_program_parents(paths, remedy::Stage::Before)?;
    // Only a name that is not there is passed over: for any other answer the open below reads it
    // and speaks with its own error.
    if !matches!(records::look(&paths.program), records::Look::NotThere)
        && let Err(refusal) = DirHandle::open_anchor_with(&paths.program, LIST | READ_CONTROL)?
    {
        // text: refusal_entry-1
        return Err(anchor_refusal(paths, &refusal, false));
    }
    for name in [CHECKOUT, CONNECT] {
        if account::find(name)?.is_some() {
            // text: entry-1
            return Err(Error::Refused(format!(
                "an account named {name} exists, and no manifest of the installation records it"
            )));
        }
    }
    if service::manager()?.open(SERVICE)?.is_some() {
        // text: entry-2
        return Err(Error::Refused(format!(
            "a service named {SERVICE} exists, and no manifest of the installation records it"
        )));
    }
    for (directory, accepted) in [(&paths.program, false), (&paths.data, data_accepted)] {
        if accepted {
            continue;
        }
        match records::look(directory) {
            records::Look::NotThere => {}
            records::Look::There => {
                // text: entry-3
                return Err(Error::Refused(format!(
                    "{} exists, and no manifest of the installation records it",
                    directory.display()
                )));
            }
            records::Look::Unread(error) => {
                // text: entry-4
                return Err(Error::Refused(format!(
                    "a look at {} failed ({error}), so the setup program cannot tell whether something that this installation did not make is there",
                    directory.display()
                )));
            }
        }
    }
    Ok(Entry::Fresh)
}

/// Makes a directory with its descriptor unless one is there: what is there was checked on its
/// handle when the installation was entered.
fn made_if_missing(path: &Path, readable: &Principals, what: &str) -> Result<(), Error> {
    if path
        .try_exists()
        // text: made_if_missing-1
        .map_err(io_error(format!("looking at {}", path.display())))?
    {
        return Ok(());
    }
    fresh::directory_at(path, SdKind::AdminDir, readable).map_err(io_error(what))
}

/// Puts a program file in the program directory: made new with its descriptor when it is not there;
/// a file that an earlier run of this installation put there was checked on its handle when the
/// installation was entered, and is overwritten as it is, keeping the descriptor that was checked.
fn install_program_file(source: &Path, target: &Path) -> io::Result<()> {
    let mut from = fs::File::open(source)?;
    let there = target.try_exists().map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("a look at {} failed ({error})", target.display()),
        )
    })?;
    if there {
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
    check_data_parent_at(paths, remedy::Stage::Before)
}

/// [`check_data_parent`] with the stage of the run that reads the folder, so that a refusal says
/// only what is so of the run's changes. No refusal of the folder tells the administrator to move,
/// rename or remove it, for any purpose: it holds the data directory.
fn check_data_parent_at(paths: &Paths, stage: remedy::Stage) -> Result<Option<ffi::Handle>, Error> {
    let parent = paths.data_parent();
    // Every folder above the data parent is another program's: the known folder `ProgramData` and
    // the folders above it. The data parent itself is the installation's and is read below.
    check_ancestors(parent, remedy::Tree::Data, stage)?;
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
    // text: install_check_data_parent_at-1
    let handle = match ffi::Handle::new(raw, "opening the data directory's parent folder") {
        Ok(handle) => handle,
        // The data parent is not there: the installation makes it.
        Err(failure) if failure.code == ERROR_FILE_NOT_FOUND => {
            return Ok(None);
        }
        // Every folder above the data parent was read before this open, so a path that is not
        // found is a folder on its path that is gone since: a refusal, never an absent data parent.
        // The words name the open that failed, the data parent's, and its error: no call opened
        // the folder that is gone.
        Err(failure) if failure.code == ERROR_PATH_NOT_FOUND => {
            let shown = parent.display().to_string();
            // text: check_data_parent_at-1
            return Err(Error::Refused(remedy::ancestor_refusal(
                &remedy::Subject::shared(
                    &shown,
                    remedy::AncestorFault::Unreadable(&failure.to_string()),
                ),
                remedy::Tree::Data,
                stage,
            )));
        }
        Err(failure) if failure.code == ERROR_SHARING_VIOLATION => {
            // text: refusal_check_data_parent_at-5
            return Err(parent_refusal(
                paths,
                "another program holds it open: with a right to delete or rename it, or without sharing it for reading and writing, and the check needs both so that it can hold the folder against a rename or a delete",
                ParentCure::Close,
            ));
        }
        // Nothing shows who made a folder that cannot be opened: it is moved aside, never corrected
        // into place and never removed.
        Err(failure) => {
            // text: refusal_check_data_parent_at-4
            return Err(parent_refusal(
                paths,
                &format!("it could not be opened to be checked ({failure})"),
                ParentCure::Unreadable,
            ));
        }
    };
    check_data_parent_handle(paths, &handle, stage)?;
    Ok(Some(handle))
}

/// The checks of the folder above the data directory that rest on its own handle: not a reparse
/// point, a folder, and no list that another account may change. The handle is the one that opened
/// the folder, or the one of the call that made it.
fn check_data_parent_handle(
    paths: &Paths,
    handle: &ffi::Handle,
    stage: remedy::Stage,
) -> Result<(), Error> {
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
        // text: install_check_data_parent_at-2
        return Err(ffi::last("reading the data directory's parent folder").into());
    }
    if tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        // text: refusal_check_data_parent_at-3
        return Err(parent_refusal(
            paths,
            "it is a reparse point, such as a link or a mounted folder",
            ParentCure::Link(stage),
        ));
    }
    if tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
        // text: refusal_check_data_parent_at-2
        return Err(parent_refusal(
            paths,
            "it is not a folder",
            ParentCure::NotAFolder,
        ));
    }
    if let Some(finding) = acl::changeable_by_others_on(handle, false)? {
        // The handle's own owner tells whether the system's class made the folder.
        let cure = match owner_outside_class(handle)? {
            Some(owner) => ParentCure::Owned(owner),
            None => ParentCure::Correct(presence_of(&paths.data)),
        };
        // text: refusal_check_data_parent_at-1
        return Err(parent_refusal(paths, &finding.to_string(), cure));
    }
    Ok(())
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
    // text: parent_refusal-1
    Error::Refused(format!(
        "{} is the folder in which the installation keeps the boundary's data. It is refused because {why}. Whoever owns that folder, or can write or delete in it, could put data of their own in its place while the broker runs as the system. {remedy}",
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
    /// What the run that holds these does: a refusal of a child that appeared since the check says only
    /// what the purpose allows.
    purpose: Purpose,
    _parent: ffi::Handle,
    /// What this run made of the data directory's place, each object through the handle of the
    /// call that made it. Empty where the directory and the folder above it were there.
    made: Made,
    data: DirHandle,
    staging: Option<DirHandle>,
    journal: Option<DirHandle>,
    run: Option<DirHandle>,
}

/// What a run made of the data directory's place, each object held through the handle of the call
/// that made it. The handle holds an identity and no right to delete: it is opened with full sharing
/// and without the right to delete, so that no later open of the product or of the system meets a
/// handle of the run that holds the right (an open that does not share delete would be refused by
/// it). A cleanup opens the same object again through that handle, never through a path, with the
/// right to delete, marks it, and closes every handle of it before it turns to the folder above, so
/// that an object that was put at the path since (or a link) is never taken for what this run made.
/// The handles are held until the first manifest is written: after that a removal finds the objects
/// by the manifest.
#[derive(Debug, Default)]
struct Made {
    /// The folder above the data directory, where this run's own call made it.
    parent: Option<ffi::Handle>,
    /// The data directory, where this run's own call made it.
    directory: Option<ffi::Handle>,
}

/// Marks the object behind `identity` for removal: opens it again through that handle, with the right
/// to delete, marks it through the new handle (the name goes when the object has no other handle and
/// no entry) and closes the new handle. The words are the platform's refusal, of the reopen or of the
/// mark.
fn mark_for_removal(identity: &ffi::Handle) -> Result<(), String> {
    let deleter = identity.reopen(DELETE | FILE_READ_ATTRIBUTES).map_err(|failure| {
        remedy::platform_error(
            "the platform refused to open it again through its own handle to mark it for removal",
            failure.code,
        )
    })?;
    super::root::delete(&deleter).map_err(|failure| {
        remedy::platform_error("the platform refused to mark it for removal", failure.code)
    })
}

impl Made {
    /// Whether this run made nothing of the data directory's place.
    fn is_empty(&self) -> bool {
        self.parent.is_none() && self.directory.is_none()
    }

    /// Marks what this run made for removal: the data directory first, through its own handle, and
    /// every handle of it is closed before the folder above it is marked, where this run made that
    /// too, and only once the directory is gone. The caller has closed its own handles of both.
    /// Returns what came of the directory and of the folder: each is [`Taken::NotMade`] where this
    /// run did not make it, [`Taken::Marked`] where the platform marked it, and [`Taken::Stays`]
    /// with the platform's refusal of the reopen or the mark (a folder that is not tried because
    /// the directory in it stays says so).
    fn take_away(self) -> (Taken, Taken) {
        let Made { parent, directory } = self;
        let directory = match directory {
            None => Taken::NotMade,
            Some(identity) => {
                let taken = match mark_for_removal(&identity) {
                    Ok(()) => Taken::Marked,
                    Err(words) => Taken::Stays(words),
                };
                // The identity is the last handle of the directory that this run holds: it is
                // closed before the folder is marked, which finds it empty only when the directory
                // has gone.
                drop(identity);
                taken
            }
        };
        let folder = match parent {
            None => Taken::NotMade,
            Some(_) if matches!(directory, Taken::Stays(_)) => {
                Taken::Stays("the data directory in it stays".to_owned())
            }
            Some(identity) => match mark_for_removal(&identity) {
                Ok(()) => Taken::Marked,
                Err(words) => Taken::Stays(words),
            },
        };
        (directory, folder)
    }

    /// The error of a step that failed after this run made something of the data directory's place,
    /// with what was done about what it made: the words of the failure, then what was removed and
    /// what stays. An error where this run made nothing is returned as it is. The caller has closed
    /// every handle of the run to what it made, so only the handles of `self` remain.
    fn after(self, paths: &Paths, error: Error) -> Error {
        if self.is_empty() {
            return error;
        }
        let (directory, folder) = self.take_away();
        let ending = remedy::data_made_ending(
            &directory,
            &paths.data.display().to_string(),
            &folder,
            &paths.data_parent().display().to_string(),
        );
        let words = error.to_string();
        if matches!(error, Error::Refused(_)) {
            // text: made_after-1
            Error::Refused(format!("{words} {ending}"))
        } else {
            // text: made_after-2
            Error::Failed(format!("{words}. {ending}"))
        }
    }
}

impl std::fmt::Debug for DataHolds {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("DataHolds").finish_non_exhaustive()
    }
}

impl DataHolds {
    /// The failure of a step after this run made the data directory or the folder above it, and the
    /// cleanup of what it made: every handle of the run to those objects is closed first (the folders
    /// and directories held here, which are copies of the handles of the creating calls), and then
    /// what the run made is marked for removal through the handles of the calls that made it.
    fn undo(self, error: Error) -> Error {
        let DataHolds {
            paths,
            purpose: _,
            _parent,
            made,
            data,
            staging,
            journal,
            run,
        } = self;
        drop((_parent, data, staging, journal, run));
        made.after(&paths, error)
    }

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
            // text: directory-1
            Error::Failed(format!(
                "{} was made and is gone again",
                which.path(&self.paths).display()
            ))
        })?;
        let shown = which.path(&self.paths).display().to_string();
        if let Some(why) = not_a_plain_directory(&handle, &shown)? {
            // text: refusal_directory-2
            return Err(child_refusal(
                &self.paths,
                self.purpose,
                &name,
                why,
                &Origin::Foreign,
            ));
        }
        if !created {
            // It appeared between the listing and this call: it is checked like one that was there.
            if let Some(why) = check_held_object(&handle)? {
                // text: refusal_directory-1
                return Err(child_refusal(
                    &self.paths,
                    self.purpose,
                    &name,
                    &why,
                    &origin_of(&handle),
                ));
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

/// The refusal of a data directory that is there and is not the installation's own. The ending
/// comes from what the directory's own handle showed, and one refusal gives one ending: a step only
/// where a read that succeeded shows what it is, and no step where a read failed.
fn data_refusal(paths: &Paths, why: &str, origin: &Origin, purpose: Purpose) -> Error {
    let ending = with_grounds(paths, purpose, |grounds| {
        remedy::data_ending(grounds, origin, why == remedy::CASE_SENSITIVE_WHY)
    });
    // text: data_refusal-1
    Error::Refused(format!(
        "{} is the boundary's data directory (its manifest, its journal and the roots of its operations). It is refused because {why}. {ending}",
        paths.data.display()
    ))
}

/// Calls `f` with the grounds of a run: its purpose, and the reads that show what the computer
/// holds of the rest of the installation. The reads are made only when `f` asks for a clearance, and
/// only for an installation: a removal, a repair and a status report never read for it. The folder
/// above the data directory was checked and held before any caller gets here, so the reads may work
/// in it.
fn with_grounds<T>(
    paths: &Paths,
    purpose: Purpose,
    f: impl FnOnce(&remedy::Grounds<'_>) -> T,
) -> T {
    let reads = || standing_of(paths);
    f(&remedy::Grounds::new(purpose, &reads))
}

/// What the reads of this run show of the rest of the installation: nothing found only where the
/// service, both accounts, the accounts that carry the comment and the policy were each read and
/// showed nothing of the installation. A read that finds something or fails leaves the answer at "may be installed", with the words that
/// say which read found what, or failed with which error.
fn standing_of(paths: &Paths) -> remedy::Standing {
    match something_of_the_installation(paths) {
        None => remedy::Standing::NothingFound,
        Some(why) => remedy::Standing::MayBeInstalled(why),
    }
}

/// The first read of the service, of the two accounts by name, of the accounts that carry the
/// installation's comment and of the policy that shows a part of the installation or fails, in words; none where each read succeeded and showed nothing. A read that
/// fails is not "nothing found".
fn something_of_the_installation(paths: &Paths) -> Option<String> {
    match service::manager().and_then(|manager| manager.open(SERVICE)) {
        Ok(None) => {}
        Ok(Some(_)) => return Some("the broker's service is there".to_owned()),
        Err(error) => {
            return Some(format!("a read of the broker's service failed ({error})"));
        }
    }
    for name in [CHECKOUT, CONNECT] {
        match account::find(name) {
            Ok(None) => {}
            Ok(Some(_)) => return Some(format!("the account {name} is there")),
            Err(error) => {
                return Some(format!("a lookup of the account {name} failed ({error})"));
            }
        }
    }
    // One enumeration of the local accounts, for the comment that the installation gives them: an
    // account that an administrator renamed is still found by it. Another account with the same
    // comment is found too, which only withholds the move, the safe direction.
    match account::carrying_the_installation_comment() {
        Ok(names) if names.is_empty() => {}
        Ok(names) => {
            return Some(format!(
                "an account carries the comment that the installation gives its accounts: {}",
                names.join(", ")
            ));
        }
        Err(error) => {
            return Some(format!(
                "an enumeration of the local accounts failed ({error})"
            ));
        }
    }
    // The folder above the data directory was checked and held by the caller, and is where the
    // channel makes its own temporary directory.
    match Channel::new(paths.data_parent()).effective() {
        Ok((_, policy)) if policy.holds_our_rules() => {
            Some("the policy holds a rule of the installation".to_owned())
        }
        Ok(_) => None,
        Err(error) => Some(format!("a read of the policy failed ({error})")),
    }
}

/// The refusal of a data directory when a call on it failed, the open of it or a read of its open
/// handle (`read` names which): the words name that read and its error, and nothing more. The failed
/// read showed nothing of who made the directory or of what it holds, so the words give no step and
/// no forecast; in particular they never tell the administrator to move the directory aside, which
/// at a removal or a repair would take away the records that the installation keeps in it. Any
/// other kind of failure is returned as it is.
fn data_unread(paths: &Paths, read: &str, error: Error) -> Error {
    match error {
        Error::Win(failure) => {
            // text: data_unread-1
            Error::Refused(format!(
                "{} is the boundary's data directory (its manifest, its journal and the roots of its operations). The setup program goes no further with it, because {read} failed ({failure}) and showed nothing of what it is.",
                paths.data.display()
            ))
        }
        other => other,
    }
}

/// What the data directory must be, read on its open handle: a plain directory, and what
/// [`check_data_object`] requires. Returns the reason that it is not, with what its handle shows of
/// who made it.
fn data_directory_reason(
    paths: &Paths,
    handle: &ffi::Handle,
) -> Result<Option<(String, Origin)>, Error> {
    if let Some(why) = not_a_plain_directory(handle, &paths.data.display().to_string())? {
        return Ok(Some((why.to_owned(), Origin::Foreign)));
    }
    Ok(check_data_object(handle)?.map(|why| (why, origin_of(handle))))
}

/// The refusal of a data directory that this run made and then refused. The words that say what was
/// done about what the run made, and what could not be, are added by [`Made::after`], which takes the
/// objects away through the handles of the calls that made them.
fn refuse_made_data_directory(paths: &Paths, why: &str) -> Error {
    // text: data_made_refusal-1
    Error::Refused(format!(
        "{} is the boundary's data directory. This run made it, and it is refused because {why}.",
        paths.data.display()
    ))
}

/// The refusal of what is inside the data directory: a child that is not the installation's own, or
/// is not what the manifest says.
fn child_refusal(
    paths: &Paths,
    purpose: Purpose,
    name: &OsStr,
    why: &str,
    origin: &Origin,
) -> Error {
    entry_refusal(paths, purpose, &paths.data, name, why, origin)
}

/// The refusal of an entry that the layout never gives as a record (a name it does not give, what is
/// in `staging`, a directory that no manifest records): it holds nothing the manifest and the
/// journal say, and it takes its remedy from what its own handle showed, like a record: it is named
/// to remove only when the handle shows the system's class, and moved aside when it shows another
/// account's, a link or a second name: both only at an installation whose reads found nothing of
/// the installation.
fn removal_refusal(
    paths: &Paths,
    purpose: Purpose,
    dir: &Path,
    name: &OsStr,
    why: &str,
    origin: &Origin,
) -> Error {
    refusal_with(
        paths,
        purpose,
        dir.join(name),
        why,
        EntryKind::Other,
        origin,
        None,
    )
}

/// The refusal of the manifest, or of a directory of the data directory, that the manifest's own
/// record does not show: the entry's own handle passed its checks, so the remedy comes from the
/// manifest's record of it, which says that the manifest does not record the entry.
fn unrecorded_refusal(paths: &Paths, purpose: Purpose, name: &OsStr, why: &str) -> Error {
    refusal_with(
        paths,
        purpose,
        paths.data.join(name),
        why,
        kind_of(paths, &paths.data, name, true),
        &Origin::System,
        Some(remedy::Record::NotRecorded),
    )
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
        Ok(summary) => Origin::Owned(summary.owner),
        Err(error) => Origin::Unknown(error.to_string()),
    }
}

/// What an opened entry's handle shows about who made it, given what the layout gives at its name:
/// a link, a file with a second name and an object of another kind than the layout gives there are
/// not the installation's, and any other object is read for its owner.
fn origin_of_opened(opened: &Opened, kind: EntryKind) -> Origin {
    let shape = match opened.kind {
        Kind::ReparsePoint => Shape::Link,
        Kind::File => Shape::File {
            names: opened.links,
        },
        Kind::Directory => Shape::Directory,
    };
    remedy::origin_of_shape(kind, shape, &|| origin_of(&opened.handle))
}

/// Why a child that was lost is refused: an open that failed was refused, and a child that is not
/// where or what the listing said was opened and found changed or moved.
fn lost_reason(lost: &Lost) -> String {
    match lost {
        Lost::Refused(_) => format!("it could not be opened to be checked ({lost})"),
        other => format!("it changed or moved while it was read ({other})"),
    }
}

/// What the loss of a child shows: a list that refuses the administrator, a program that holds the
/// child, or nothing. A child that is gone since the listing is the caller's to treat as absent.
fn origin_of_lost(lost: &Lost) -> Origin {
    match lost {
        Lost::Refused(code) => remedy::origin_of_open_error(*code, &lost.to_string()),
        other => Origin::Changed(other.to_string()),
    }
}

/// The refusal of one entry in a directory of the installation. The remedy comes from what the
/// entry's own handle showed (`origin`) and from the lookup of the manifest, and never from the
/// words of the reason: for a name the layout gives as a record, the system's class's own is
/// corrected while a manifest may be there, another account's is moved out only at an installation
/// whose reads found nothing of the installation (otherwise its owner is named, with the one step
/// that gives the ownership back), and one that could not be read gets no step; any other name, and
/// what is in `staging`, is named to remove only at such an installation.
fn entry_refusal(
    paths: &Paths,
    purpose: Purpose,
    dir: &Path,
    name: &OsStr,
    why: &str,
    origin: &Origin,
) -> Error {
    refusal_with(
        paths,
        purpose,
        dir.join(name),
        why,
        kind_of(paths, dir, name, true),
        origin,
        None,
    )
}

/// The refusal of a private root that no journal names: its own handle decides, and only one that
/// the system's class owns is named to remove, at an installation whose reads found nothing of the
/// installation.
fn unnamed_root_refusal(
    paths: &Paths,
    purpose: Purpose,
    dir: &Path,
    name: &OsStr,
    why: &str,
    origin: &Origin,
) -> Error {
    refusal_with(
        paths,
        purpose,
        dir.join(name),
        why,
        kind_of(paths, dir, name, false),
        origin,
        None,
    )
}

fn refusal_with(
    paths: &Paths,
    purpose: Purpose,
    entry: PathBuf,
    why: &str,
    kind: EntryKind,
    origin: &Origin,
    record: Option<remedy::Record>,
) -> Error {
    let manifest = presence_of(&paths.manifest);
    let ending = with_grounds(paths, purpose, |grounds| {
        let remedy = remedy::choose(grounds, kind, origin, &manifest, record);
        remedy::ending(&entry, &remedy, origin, kind, &manifest, record)
    });
    // text: refusal_with-1
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
/// them for one. The read has three answers: the flag is set, the flag is clear, and the read
/// failed. A failed read is the error, whatever its code, with one exception: where the system
/// answers `ERROR_INVALID_PARAMETER` (it does not know the class for this volume), a second read of
/// the volume's own flags can show that the volume has no case sensitive search, so that no
/// directory on it separates names by case; only then does the answer count as clear.
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
        // text: install_case_sensitive_reason-1
        let unread = ffi::error(
            code,
            "reading whether the data directory separates names by case",
        );
        if code != ERROR_INVALID_PARAMETER {
            return Err(unread.into());
        }
        return match volume_searches_by_case(handle) {
            Ok(false) => Ok(None),
            Ok(true) => Err(unread.into()),
            Err(volume) => {
                // text: install_case_sensitive_reason-2
                Err(ffi::error(volume.code, format!("{unread}, and then {}", volume.what)).into())
            }
        };
    }
    // The flag that says the directory separates names that differ only by case.
    const CASE_SENSITIVE_DIRECTORY: u32 = 1;
    Ok((info.Flags & CASE_SENSITIVE_DIRECTORY != 0).then(|| remedy::CASE_SENSITIVE_WHY.to_owned()))
}

/// Whether the volume that holds the object on `handle` supports case sensitive search, which is
/// the flag `FILE_CASE_SENSITIVE_SEARCH` of `GetVolumeInformationByHandleW`. A volume without it
/// cannot hold two names that differ only by case. NTFS sets it, so a system that does not know
/// the per-directory class and holds the directory on NTFS gets `true` here, and its read stays an
/// error.
fn volume_searches_by_case(handle: &ffi::Handle) -> ffi::Result<bool> {
    let mut flags = 0_u32;
    // SAFETY: the handle is open, the call writes the flags and nothing else, and every other
    // output is not asked for.
    if unsafe {
        GetVolumeInformationByHandleW(
            handle.raw(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut flags,
            std::ptr::null_mut(),
            0,
        )
    } == 0
    {
        // text: install_volume_searches_by_case-1
        return Err(ffi::last(
            "reading the flags of the volume that holds the data directory",
        ));
    }
    Ok(flags & FILE_CASE_SENSITIVE_SEARCH != 0)
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
        return Ok(Some(finding.to_string()));
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
        // text: install_protect_handle-1
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
        // text: install_attributes_of-1
        return Err(ffi::last(format!("reading {what}")).into());
    }
    Ok(tag.FileAttributes)
}

/// The reason an open object is not the plain directory the installation uses: it is a link, or it
/// is not a directory.
fn not_a_plain_directory(handle: &ffi::Handle, shown: &str) -> Result<Option<&'static str>, Error> {
    let attributes = attributes_of(handle, shown)?;
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Ok(Some("it is a reparse point"));
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
        // text: install_file_key-1
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
/// only opened, and with [`FILE_CREATE`] it is only made. The handle shares read and write only, so
/// nothing renames or deletes the directory while it is held. Returns the handle and whether this
/// call made the directory, or none when [`FILE_OPEN`] found nothing or [`FILE_CREATE`] found
/// something there.
fn open_directory_relative(
    parent: &ffi::Handle,
    name: &OsStr,
    disposition: u32,
    descriptor: Option<&sd::OwnedSd>,
    access: u32,
) -> Result<Option<(ffi::Handle, bool)>, Error> {
    open_directory_at(Some(parent), name, disposition, descriptor, access)
}

/// [`open_directory_relative`] with no parent handle where `name` is a full path in the platform's own
/// form (`\??\C:\...`): the call that makes a directory returns the handle of the directory that it
/// made. With [`FILE_CREATE`] the call only makes: it returns none where something was there already.
fn open_directory_at(
    parent: Option<&ffi::Handle>,
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
        RootDirectory: parent.map_or(std::ptr::null_mut(), ffi::Handle::raw),
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
            // An object that this call makes is held for the run's cleanup, which opens it again
            // through this handle: it shares everything and holds no right to delete, so that no
            // open of the product or of the system is refused by it. An object that is only opened
            // is held against a rename or a delete.
            if disposition == FILE_CREATE {
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
            } else {
                FILE_SHARE_READ | FILE_SHARE_WRITE
            },
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
        if disposition == FILE_CREATE && code == ERROR_ALREADY_EXISTS {
            return Ok(None);
        }
        // The name that has no parent is a path in the platform's own form, shown in the usual one.
        let shown = name.to_string_lossy();
        let shown = shown.strip_prefix(r"\??\").unwrap_or(&shown);
        // text: open_directory_relative-1
        return Err(ffi::error(
            code,
            format!(
                "{} {}{}",
                // With `FILE_OPEN_IF` the same call makes a directory that is not there.
                match disposition {
                    FILE_OPEN => "opening",
                    FILE_CREATE => "making",
                    _ => "opening or making",
                },
                shown,
                if parent.is_some() {
                    " beneath a held directory"
                } else {
                    ""
                }
            ),
        )
        .into());
    }
    // text: install_open_directory_relative-1
    let handle = ffi::Handle::new(
        raw,
        if parent.is_some() {
            "opening a directory beneath a held directory"
        } else {
            "opening a directory by its full path"
        },
    )?;
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
    /// Whether the earlier-state record was opened and checked.
    prior: bool,
    /// The manifest's replacements that were opened and checked.
    replacements: Vec<OsString>,
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
fn inspect_data_directory(
    paths: &Paths,
    purpose: Purpose,
    data: &DirHandle,
) -> Result<Inspected, Error> {
    let listed = data.children()?;
    let mut inspected = Inspected {
        manifest: None,
        staging: None,
        journal: None,
        run: None,
        prior: false,
        replacements: Vec::new(),
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
        // With no manifest, the first entry that is still there is read on its own handle, whatever
        // its name: it takes its remedy from what the handle shows. An entry that is gone since the
        // listing is absent, and a directory whose entries are all gone is empty.
        for first in &listed {
            let shown = OsString::from_wide(&first.name);
            let kind = kind_of(paths, &paths.data, &shown, true);
            let access = if matches!(
                kind,
                EntryKind::Staging | EntryKind::Journal | EntryKind::Run
            ) {
                LIST | READ_CONTROL
            } else {
                READ_CONTROL
            };
            let origin = match data.open_child(first, access)? {
                Ok(opened) => origin_of_opened(&opened, kind),
                Err(Lost::Gone) => continue,
                Err(lost) => origin_of_lost(&lost),
            };
            return Err(entry_refusal(
                paths,
                purpose,
                &paths.data,
                &shown,
                "no manifest records this directory, and a directory that no manifest records must be empty",
                &origin,
            ));
        }
        return Ok(inspected);
    }
    for child in &listed {
        let shown = OsString::from_wide(&child.name);
        let expected = match names.iter().find(|(name, _)| same_name(&child.name, name)) {
            Some((_, expected)) => expected,
            // A manifest that was being replaced when a run stopped.
            None if is_manifest_replacement(&shown.to_string_lossy()) => &Kind::File,
            None => {
                let origin = match data.open_child(child, READ_CONTROL)? {
                    Ok(opened) => origin_of_opened(&opened, EntryKind::Other),
                    // An entry that is gone since the listing is absent.
                    Err(Lost::Gone) => continue,
                    Err(lost) => origin_of_lost(&lost),
                };
                return Err(removal_refusal(
                    paths,
                    purpose,
                    &paths.data,
                    &shown,
                    "the layout does not give that name there",
                    &origin,
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
                // text: refusal_inspect_data_directory-6
                return Err(child_refusal(
                    paths,
                    purpose,
                    &shown,
                    &lost_reason(&lost),
                    &origin_of_lost(&lost),
                ));
            }
        };
        match (opened.kind, *expected) {
            (Kind::ReparsePoint, _) => {
                // text: refusal_inspect_data_directory-5
                return Err(child_refusal(
                    paths,
                    purpose,
                    &shown,
                    "it is a reparse point",
                    &Origin::Foreign,
                ));
            }
            (Kind::File, Kind::File) | (Kind::Directory, Kind::Directory) => {}
            (Kind::Directory, _) => {
                // text: refusal_inspect_data_directory-4
                return Err(child_refusal(
                    paths,
                    purpose,
                    &shown,
                    "it is a directory, not a file",
                    &Origin::Foreign,
                ));
            }
            (Kind::File, _) => {
                // text: refusal_inspect_data_directory-3
                return Err(child_refusal(
                    paths,
                    purpose,
                    &shown,
                    "it is a file, not a directory",
                    &Origin::Foreign,
                ));
            }
        }
        if opened.kind == Kind::File && opened.links > 1 {
            // text: refusal_inspect_data_directory-2
            return Err(child_refusal(
                paths,
                purpose,
                &shown,
                "it has more than one name",
                &Origin::Foreign,
            ));
        }
        if let Some(why) = check_held_object(&opened.handle)? {
            // text: refusal_inspect_data_directory-1
            return Err(child_refusal(
                paths,
                purpose,
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
        } else if same_name(&child.name, &names[1].0) {
            inspected.prior = true;
        } else if is_manifest_replacement(&shown.to_string_lossy()) {
            inspected.replacements.push(shown.clone());
        }
    }
    inspect_layout(
        paths,
        purpose,
        &paths.staging,
        inspected.staging.as_ref(),
        Layout::Staging,
    )?;
    inspect_layout(
        paths,
        purpose,
        &paths.journal,
        inspected.journal.as_ref(),
        Layout::Journal,
    )?;
    inspect_layout(
        paths,
        purpose,
        &paths.run,
        inspected.run.as_ref(),
        Layout::Run,
    )?;
    let manifest = Manifest::load(&paths.manifest)?;
    let records = |path: &Path| {
        manifest
            .find(ObjectKind::Directory, &path.display().to_string())
            .is_some()
    };
    if !records(&paths.data) {
        return Err(unrecorded_refusal(
            paths,
            purpose,
            &names[0].0,
            "its manifest does not record this directory, and a directory that no manifest records must be empty",
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
            return Err(unrecorded_refusal(
                paths,
                purpose,
                path.file_name().unwrap_or_default(),
                "the manifest holds no record of this directory, and a directory that the manifest holds no record of must be empty",
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
    Ok(owner_outside_class(handle)?.map(|owner| format!("it is owned by {owner}")))
}

/// The identifier of the handle's owner, where the owner is not the system or the Administrators
/// group.
fn owner_outside_class(handle: &ffi::Handle) -> Result<Option<String>, Error> {
    let summary = sd::summary_of_handle(handle)?;
    Ok((![SYSTEM, ADMINISTRATORS].contains(&summary.owner.as_str())).then_some(summary.owner))
}

/// The reason an object that every account may read is not the installation's own: another account
/// may change it, or the system and the administrators do not own it. The proof's scratch space is
/// made readable by every account, and what is made in it takes that list.
fn check_readable_object(handle: &ffi::Handle) -> Result<Option<String>, Error> {
    if let Some(finding) = acl::changeable_by_others_on(handle, false)? {
        return Ok(Some(finding.to_string()));
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
    purpose: Purpose,
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
    let named = if layout == Layout::Run && !children.is_empty() {
        let named = roots_named_by_the_journal(paths)?;
        #[cfg(feature = "testing")]
        testing::after_a_read("journal");
        named
    } else {
        NamedRoots::default()
    };
    for child in children {
        let shown = OsString::from_wide(&child.name);
        let text = shown.to_string_lossy().into_owned();
        let Some(expected) = layout_kind(layout, &text) else {
            let origin = match held.open_child(&child, READ_CONTROL)? {
                Ok(opened) => origin_of_opened(&opened, EntryKind::Other),
                // An entry that is gone since the listing is absent.
                Err(Lost::Gone) => continue,
                Err(lost) => origin_of_lost(&lost),
            };
            return Err(removal_refusal(
                paths,
                purpose,
                dir,
                &shown,
                "the installation does not give that name there",
                &origin,
            ));
        };
        if layout == Layout::Run && !named.roots.contains(&text) {
            // Its own handle decides: only a root that the system's class owns is named to remove.
            let origin = match held.open_child(&child, LIST | READ_CONTROL)? {
                Ok(opened) => origin_of_opened(&opened, EntryKind::UnnamedRoot),
                Err(Lost::Gone) => continue,
                Err(lost) => origin_of_lost(&lost),
            };
            let damaged: Vec<(&str, &str)> = named
                .damaged
                .iter()
                .map(|(id, damage)| (id.as_str(), damage.as_str()))
                .collect();
            return Err(unnamed_root_refusal(
                paths,
                purpose,
                dir,
                &shown,
                &remedy::unnamed_root_why(&damaged),
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
                    purpose,
                    dir,
                    &shown,
                    &lost_reason(&lost),
                    &origin_of_lost(&lost),
                ));
            }
        };
        match (opened.kind, expected) {
            (Kind::ReparsePoint, _) => {
                return Err(entry_refusal(
                    paths,
                    purpose,
                    dir,
                    &shown,
                    "it is a reparse point",
                    &Origin::Foreign,
                ));
            }
            (Kind::File, Kind::File) | (Kind::Directory, Kind::Directory) => {}
            (Kind::Directory, _) => {
                return Err(entry_refusal(
                    paths,
                    purpose,
                    dir,
                    &shown,
                    "it is a directory, not a file",
                    &Origin::Foreign,
                ));
            }
            (Kind::File, _) => {
                return Err(entry_refusal(
                    paths,
                    purpose,
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
                purpose,
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
                purpose,
                dir,
                &shown,
                &why,
                &origin_of(&opened.handle),
            ));
        }
        if layout == Layout::Staging && opened.kind == Kind::Directory {
            let inner = DirHandle::from_opened(opened)?;
            if text.starts_with("proof-") {
                inspect_proof_directory(paths, purpose, &dir.join(&shown), &inner)?;
            } else {
                inspect_within(paths, Scope::Staging(purpose), &dir.join(&shown), &inner, 1)?;
            }
        }
    }
    Ok(())
}

/// Which tree a check below the data directory or the program directory reads.
#[derive(Clone, Copy)]
enum Scope {
    /// A directory of `staging`: a refusal takes its remedy from the entry's own handle.
    Staging(Purpose),
    /// The program directory: a refusal names the owner and the list to correct. `recorded` says
    /// whether a manifest records the installation, which decides whether the words promise a repair
    /// or say that the manifest records the directory.
    Program { recorded: bool },
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
    /// The entry is a link: remove the link itself and not what it points to.
    RemoveLink,
    /// The configuration file that the installation makes empty is not empty: remove it, and a
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

/// The refusal of an entry in the program directory: the owner and the list to correct, or the entry
/// to remove, whichever its reason shows. `recorded` says whether a manifest records the
/// installation: a repair makes the program files again, and the manifest records the directory,
/// only where one does.
fn program_refusal(
    paths: &Paths,
    dir: &Path,
    name: &OsStr,
    why: &str,
    cure: Cure,
    recorded: bool,
) -> Error {
    let entry = dir.join(name);
    let kept = remedy::program_keeping(recorded, false);
    let kept_directory = remedy::program_keeping(recorded, true);
    let remedy = match cure {
        Cure::OwnerAndList => format!(
            "Correct what the reason names (the Administrators group, or the system, owns it, and only the system, the Administrators group and the installer service may change it), then run the setup program again. {kept}"
        ),
        Cure::RemoveEntry => {
            remedy::program_removal_advice(&entry.display().to_string(), false, recorded)
        }
        Cure::RemoveLink => {
            remedy::program_removal_advice(&entry.display().to_string(), true, recorded)
        }
        Cure::EmptyConfig => remedy::empty_config_advice(&entry.display().to_string(), recorded),
        Cure::Volume => format!(
            "{} is on a volume that the installation does not use: it keeps its program directory on a fixed, local NTFS volume, and nothing in it can be corrected to make another volume one. {kept_directory} {}",
            entry.display(),
            remedy::supported_layout(remedy::Tree::Program)
        ),
        Cure::Open => remedy::program_open_advice(&entry.display().to_string(), kept_directory),
    };
    // text: program_refusal-1
    Error::Refused(format!(
        "{} is the boundary's program directory (the program that the service runs as the system). It is refused because of {}: {why}. Whoever owns it, or can change its list, could replace that program. {remedy}",
        paths.program.display(),
        entry.display(),
    ))
}

/// The refusal of the program directory's own name: a link or a file there is removed, the volume is
/// a refusal that no change of owner, list or open handle cures.
fn anchor_refusal(paths: &Paths, refusal: &AnchorRefusal, recorded: bool) -> Error {
    let (why, cure) = match refusal {
        AnchorRefusal::Volume(_) => (refusal.to_string(), Cure::Volume),
        AnchorRefusal::ReparsePoint => ("it is a reparse point".to_owned(), Cure::RemoveLink),
        AnchorRefusal::NotADirectory => (refusal.to_string(), Cure::RemoveEntry),
    };
    // text: refusal_anchor_refusal-1
    program_refusal(
        paths,
        paths.program.parent().unwrap_or(&paths.program),
        paths.program.file_name().unwrap_or_default(),
        &why,
        cure,
        recorded,
    )
}

/// What opening a known folder shows: the final path of the folder that its path leads to, with
/// every link followed (a link or a mounted folder at the path leads to its target), or the
/// platform's error of the open or of the read of the final path.
fn opened_final_path(folder: &Path) -> Result<String, String> {
    let wide = ffi::wide_path(folder);
    // SAFETY: the path is NUL-terminated; the call keeps nothing of it.
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    let handle =
        // text: install_opened_final_path-1
        ffi::Handle::new(raw, "opening a known folder").map_err(|error| error.to_string())?;
    final_path_of(&handle).map_err(|error| error.to_string())
}

/// A known folder as the shape check reads it: the path that the system gave and what opening it
/// showed.
fn known_folder<'a>(given: &'a str, opened: &'a Result<String, String>) -> remedy::KnownFolder<'a> {
    remedy::KnownFolder {
        given,
        opened: opened.as_ref().map(String::as_str).map_err(String::as_str),
    }
}

/// Refuses a layout whose known folders cannot hold the two trees: read first by every
/// installation, repair and removal, before any walk. Each known folder is opened with its links
/// followed and its final path is read; [`remedy::shape_refusal`] decides on the path that the
/// system gave and the final path of the folder that it opens, so that a known folder reached by
/// another name is never taken for what its spelling says. After it, a folder strictly below a known
/// folder is the installation's own.
///
/// # Errors
///
/// Returns [`Error::Refused`] naming the known folder and the reason.
pub fn check_shape(paths: &Paths, stage: remedy::Stage) -> Result<(), Error> {
    let data_parent = paths.data_parent();
    let program_data = data_parent.parent().unwrap_or(data_parent);
    let (files_path, data_path) = (
        paths.program_top.display().to_string(),
        program_data.display().to_string(),
    );
    let (files_opened, data_opened) = (
        opened_final_path(&paths.program_top),
        opened_final_path(program_data),
    );
    match remedy::shape_refusal(
        &known_folder(&files_path, &files_opened),
        &known_folder(&data_path, &data_opened),
        stage,
    ) {
        // text: check_shape-1
        Some(text) => Err(Error::Refused(text)),
        None => Ok(()),
    }
}

/// Reads every existing folder above `top`, from the volume's root down to its parent, part by
/// part: each opened on its own handle with no link followed, a plain folder, owned by the system,
/// the Administrators group or the installer service, with no entry that lets another account
/// delete or rename an entry in it, delete it, write its list or take it. The folder that holds a
/// tree is read on its own handle with the rules of its kind; what is above it is read here, since
/// an account that could rename a folder above could put a link in the place of the folder below it
/// after the installation has read that one, and the system's default lists do not give that right
/// but nothing here rests on a default. None of these folders is the installation's to make: a
/// folder that is not there refuses the run, and a root that is not there is a volume that is gone.
///
/// Every folder read here lies strictly above `top`, the first folder that the installation makes
/// (the data directory's parent) or the known folder itself (`Program Files`, which the program walk
/// reads itself), so every one of them is another program's: the known folder `ProgramData`, the
/// folders above it, a drive letter. Their refusals take the words of a folder that the installation
/// does not make.
fn check_ancestors(top: &Path, tree: remedy::Tree, stage: remedy::Stage) -> Result<(), Error> {
    use remedy::AncestorFault as Fault;
    let mut chain: Vec<&Path> = top.ancestors().skip(1).collect();
    chain.reverse();
    for (index, folder) in chain.into_iter().enumerate() {
        let shown = folder.display().to_string();
        let refuse = |fault: Fault<'_>| {
            // text: check_ancestors-1
            Error::Refused(remedy::ancestor_refusal(
                &remedy::Subject::shared(&shown, fault),
                tree,
                stage,
            ))
        };
        let unreadable =
            |error: &dyn std::fmt::Display| refuse(Fault::Unreadable(&error.to_string()));
        let unanswered =
            |error: &dyn std::fmt::Display| refuse(Fault::VolumeUnanswered(&error.to_string()));
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
        // text: install_check_ancestors-1
        let handle = match ffi::Handle::new(raw, "opening a folder above the installation") {
            Ok(handle) => handle,
            // Every folder of this walk is a known folder or above one, so none is the
            // installation's to make: a folder that is not there refuses the run. The root of the
            // volume is the first folder of the walk, and one that is not there is a volume that is
            // gone.
            Err(failure)
                if index == 0
                    && (failure.code == ERROR_FILE_NOT_FOUND
                        || failure.code == ERROR_PATH_NOT_FOUND) =>
            {
                return Err(refuse(Fault::RootMissing(&failure.to_string())));
            }
            // Any other open that failed is said to have failed with the platform's error, at the
            // root of a volume and above it alike.
            Err(failure) => return Err(unreadable(&failure)),
        };
        // The volume first, as the program directory's own open does: a file system that is not
        // NTFS, or a volume on another computer, does not answer the attribute query that follows.
        if let Some(reason) = volume_refused(&handle).map_err(|error| unanswered(&error))? {
            return Err(refuse(Fault::Volume(&reason)));
        }
        let attributes = attributes_of(&handle, "a folder above the installation")
            .map_err(|error| unreadable(&error))?;
        if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(refuse(Fault::Link));
        }
        if attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
            return Err(refuse(Fault::NotAFolder));
        }
        // A drive letter that is substituted or redirected opens as a folder of another volume: the
        // folders above its target would be left unread, so the tree is not called checked.
        if folder.parent().is_none() {
            let found = final_path_of(&handle).map_err(|error| unreadable(&error))?;
            if !remedy::is_the_volumes_own_root(&shown, &found) {
                return Err(refuse(Fault::Alias(&remedy::dos_path_of(&found))));
            }
        }
        if let Some(why) =
            acl::replaceable_by_others_on(&handle).map_err(|error| unreadable(&error))?
        {
            return Err(refuse(Fault::List(&why.to_string())));
        }
    }
    Ok(())
}

/// Reads every existing folder from [`Paths::program_top`] down to the program directory's parent,
/// part by part: each opened on its own handle with no link followed, a plain folder at the place
/// that was asked for (its final path is the expected one), owned by the system, the Administrators
/// group or the installer service, with no entry that lets another account add to it, rename or
/// delete in it, write its list or take it. The paths that the service control manager runs the
/// broker by rest on these lists. The known folder itself that is not there refuses the run; a
/// folder strictly below it that is not there is the installation's to make, and ends the walk.
///
/// The first folder of the walk is `program_top`, the system's known folder `Program Files`, which
/// other programs share; every folder strictly below it is the installation's own. The words of a
/// refusal are chosen by that ([`remedy::Subject::at`]).
///
/// # Errors
///
/// Returns [`Error::Refused`] naming the reason, or the failure of the call that looked.
pub fn check_program_parents(paths: &Paths, stage: remedy::Stage) -> Result<(), Error> {
    use remedy::AncestorFault as Fault;
    check_ancestors(&paths.program_top, remedy::Tree::Program, stage)?;
    let Some(parent) = paths.program.parent() else {
        return Ok(());
    };
    let known = paths.program_top.display().to_string();
    let mut chain: Vec<&Path> = parent
        .ancestors()
        .take_while(|folder| folder.starts_with(&paths.program_top))
        .collect();
    chain.reverse();
    for folder in chain {
        let shown = folder.display().to_string();
        let refuse = |fault: Fault<'_>| {
            // text: check_program_parents-1
            Error::Refused(remedy::ancestor_refusal(
                &remedy::Subject::at(&shown, &known, fault),
                remedy::Tree::Program,
                stage,
            ))
        };
        let unreadable =
            |error: &dyn std::fmt::Display| refuse(Fault::Unreadable(&error.to_string()));
        let unanswered =
            |error: &dyn std::fmt::Display| refuse(Fault::VolumeUnanswered(&error.to_string()));
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
        // text: install_check_program_parents-1
        let handle = match ffi::Handle::new(raw, "opening a folder above the program directory") {
            Ok(handle) => handle,
            // Only a folder strictly below the known folder is the installation's to make, and
            // nothing below a folder that is not there is there either. The known folder itself
            // that is not there refuses the run.
            Err(failure)
                if (failure.code == ERROR_FILE_NOT_FOUND
                    || failure.code == ERROR_PATH_NOT_FOUND)
                    && remedy::is_below(&shown, &known) =>
            {
                return Ok(());
            }
            // Any other answer is not an absence: the folder could not be checked, and the person
            // is told what can be done about that.
            Err(failure) => return Err(unreadable(&failure)),
        };
        if let Some(reason) = volume_refused(&handle).map_err(|error| unanswered(&error))? {
            return Err(refuse(Fault::Volume(&reason)));
        }
        let attributes = attributes_of(&handle, "a folder above the program directory")
            .map_err(|error| unreadable(&error))?;
        // A link at the known folder itself is the plain link's fault; a link strictly below it is
        // in a folder that the installation makes, which the words say.
        if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(refuse(Fault::Link));
        }
        if attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
            return Err(refuse(Fault::NotAFolder));
        }
        // The folder that the path leads to is the one that was asked for. A final path that is
        // another is said as what it is, and no cause is named: a link, a mounted folder, a short
        // name or another spelling all lead somewhere else.
        let found = final_path_of(&handle).map_err(|error| unreadable(&error))?;
        if !remedy::is_the_place_asked_for(&shown, &found) {
            return Err(refuse(Fault::Leads(&remedy::dos_path_of(&found))));
        }
        if let Some(why) =
            acl::changeable_by_others_on(&handle, false).map_err(|error| unreadable(&error))?
        {
            return Err(refuse(Fault::Writable(&why.to_string())));
        }
    }
    Ok(())
}

/// Why the volume that an open folder is on is not one that the installation uses (a file system
/// that is not NTFS, a volume on another computer, removable media, a device that is not an
/// ordinary disk), or none where it is.
fn volume_refused(handle: &ffi::Handle) -> Result<Option<String>, ffi::Error> {
    Ok(super::walk::check_volume(handle)?
        .err()
        .map(|refusal| refusal.to_string()))
}

/// A folder's final path as the system gives it, with the `\\?\` prefix of its extended form. The
/// checks compare it with the path that was supplied ([`remedy::is_the_place_asked_for`],
/// [`remedy::is_the_volumes_own_root`]); [`remedy::dos_path_of`] prints it for a person, in a
/// refusal's words alone.
fn final_path_of(handle: &ffi::Handle) -> Result<String, Error> {
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
            // text: install_final_path_of-1
            return Err(ffi::last("reading a folder's final path").into());
        }
        if (length as usize) < buffer.len() {
            buffer.truncate(length as usize);
            break;
        }
        buffer.resize(length as usize + 1, 0);
    }
    Ok(String::from_utf16_lossy(&buffer))
}

/// Reads the program directory on a handle that is held, and everything in it on its own handle:
/// no link, one name for a file, the installation's own owner, and no right for another account to
/// change it. Nothing is done to the directory before this has passed. Returns whether the
/// directory was there to be opened and approved: a removal deletes the directory only when it was.
fn check_program_directory(
    paths: &Paths,
    recorded: bool,
    stage: remedy::Stage,
) -> Result<bool, Error> {
    check_program_parents(paths, stage)?;
    // The look follows no link: a link that points nowhere is there, and gets the link's own remedy
    // from the open below, as does a name that the look could not read.
    if matches!(records::look(&paths.program), records::Look::NotThere) {
        return Ok(false);
    }
    let program = paths.program.file_name().unwrap_or_default().to_owned();
    let held = match DirHandle::open_anchor_with(&paths.program, LIST | READ_CONTROL)? {
        Ok(held) => held,
        // text: refusal_check_program_directory-2
        Err(refusal) => return Err(anchor_refusal(paths, &refusal, recorded)),
    };
    if let Some(why) = check_readable_object(held.handle())? {
        // text: refusal_check_program_directory-1
        return Err(program_refusal(
            paths,
            paths.program.parent().unwrap_or(&paths.program),
            &program,
            &why,
            Cure::OwnerAndList,
            recorded,
        ));
    }
    inspect_within(paths, Scope::Program { recorded }, &paths.program, &held, 1)?;
    Ok(true)
}

/// The one name a proof directory holds: the unlisted program. Its bytes are those of the system's
/// own `hostname.exe`, so the file holds no secret; the proof makes it with a descriptor of its own
/// kind, which lets the one boundary account under proof read and run it and nobody else but the
/// system and the administrators have any right on it.
const PROOF_PROGRAM: &str = "unlisted.exe";

/// Reads what a proof directory holds: the unlisted program and nothing else, a file with one
/// name, on its own handle, owned as the installation's own and changeable by no other account.
fn inspect_proof_directory(
    paths: &Paths,
    purpose: Purpose,
    dir: &Path,
    held: &DirHandle,
) -> Result<(), Error> {
    for child in held.children()? {
        let shown = OsString::from_wide(&child.name);
        let opened = match held.open_child(&child, READ_CONTROL)? {
            Ok(opened) => opened,
            // An entry that is gone since the listing is absent.
            Err(Lost::Gone) => continue,
            Err(lost) => {
                return Err(removal_refusal(
                    paths,
                    purpose,
                    dir,
                    &shown,
                    &lost_reason(&lost),
                    &origin_of_lost(&lost),
                ));
            }
        };
        if !shown.to_string_lossy().eq_ignore_ascii_case(PROOF_PROGRAM) {
            return Err(removal_refusal(
                paths,
                purpose,
                dir,
                &shown,
                "the installation puts nothing but the unlisted program in a proof directory",
                &origin_of_opened(&opened, EntryKind::Other),
            ));
        }
        match opened.kind {
            Kind::File if opened.links == 1 => {}
            Kind::File => {
                return Err(removal_refusal(
                    paths,
                    purpose,
                    dir,
                    &shown,
                    "it has more than one name",
                    &Origin::Foreign,
                ));
            }
            Kind::ReparsePoint => {
                return Err(removal_refusal(
                    paths,
                    purpose,
                    dir,
                    &shown,
                    "it is a reparse point",
                    &Origin::Foreign,
                ));
            }
            Kind::Directory => {
                return Err(removal_refusal(
                    paths,
                    purpose,
                    dir,
                    &shown,
                    "it is a directory, not a file",
                    &Origin::Foreign,
                ));
            }
        }
        if let Some(why) = check_readable_object(&opened.handle)? {
            return Err(removal_refusal(
                paths,
                purpose,
                dir,
                &shown,
                &why,
                &origin_of(&opened.handle),
            ));
        }
    }
    Ok(())
}

/// What the journal's read names: the private roots that it names as unfinished work, and the
/// invocations whose journal is damaged, each with its identifier and what is wrong with it. A
/// damaged journal gives only the rows before the damage.
#[derive(Default)]
struct NamedRoots {
    roots: BTreeSet<String>,
    damaged: Vec<(String, String)>,
}

/// The journal, read as the removal reads it.
fn roots_named_by_the_journal(paths: &Paths) -> Result<NamedRoots, Error> {
    use crate::journal::rows::Row;
    let mut named = NamedRoots::default();
    match records::look(&paths.journal) {
        records::Look::NotThere => return Ok(named),
        records::Look::Unread(error) => {
            // text: roots_named_by_the_journal-2
            return Err(Error::Failed(format!("reading the journal: {error}")));
        }
        records::Look::There => {}
    }
    let unfinished = super::journal::replay(&paths.journal, "")
        // text: roots_named_by_the_journal-1
        .map_err(|error| Error::Failed(format!("reading the journal: {error}")))?;
    for invocation in unfinished {
        for row in &invocation.rows {
            if let Row::RootIntent { name } | Row::RootMade { name, .. } = row {
                named.roots.insert(name.as_str().to_owned());
            }
        }
        if let Some(damage) = invocation.damage {
            named.damaged.push((invocation.id, damage));
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
        // text: file_size-1
        return Err(Error::Failed(format!(
            "reading the size of a file: {}",
            io::Error::last_os_error()
        )));
    }
    match u64::try_from(size) {
        Ok(size) => Ok(size),
        // text: file_size-2
        Err(_) => Err(Error::Failed(format!(
            "reading the size of a file: the platform gave {size}, which is not a size"
        ))),
    }
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
        // Below `staging` an entry takes its remedy from its own handle; in the program directory
        // the reason decides what is corrected or removed.
        let refuse = |why: &str, cure: Cure, origin: &Origin| match scope {
            Scope::Staging(purpose) => removal_refusal(paths, purpose, dir, &shown, why, origin),
            // text: refusal_inspect_within-2
            Scope::Program { recorded } => program_refusal(paths, dir, &shown, why, cure, recorded),
        };
        let opened = match held.open_child(&child, LIST | READ_CONTROL)? {
            Ok(opened) => opened,
            // An entry that is gone since the listing is absent, and nothing of it is left to check.
            Err(Lost::Gone) => continue,
            Err(lost) => {
                return Err(refuse(
                    &lost_reason(&lost),
                    Cure::Open,
                    &origin_of_lost(&lost),
                ));
            }
        };
        if depth > WITHIN_DEPTH {
            return Err(refuse(
                "it is nested deeper than the installation makes anything",
                Cure::RemoveEntry,
                &origin_of_opened(&opened, EntryKind::Other),
            ));
        }
        if opened.kind == Kind::ReparsePoint {
            return Err(refuse(
                "it is a reparse point",
                Cure::RemoveLink,
                &Origin::Foreign,
            ));
        }
        if opened.kind == Kind::File && opened.links > 1 {
            return Err(refuse(
                "it has more than one name",
                Cure::RemoveEntry,
                &Origin::Foreign,
            ));
        }
        if let Scope::Program { recorded } = scope {
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
                    Some(remedy::CONFIG_NOT_EMPTY_WHY)
                }
                Some(_) => None,
            };
            if let Some(why) = reason {
                let cure = if is_git_config(paths, dir, &name) && opened.kind == Kind::File {
                    Cure::EmptyConfig
                } else {
                    Cure::RemoveEntry
                };
                // text: refusal_inspect_within-1
                return Err(program_refusal(paths, dir, &shown, why, cure, recorded));
            }
        }
        if let Some(why) = check_readable_object(&opened.handle)? {
            return Err(refuse(&why, Cure::OwnerAndList, &origin_of(&opened.handle)));
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
    purpose: Purpose,
) -> Result<Option<(DirHandle, Inspected)>, Error> {
    let name = paths
        .data
        .file_name()
        // text: inspect_existing_data-1
        .ok_or_else(|| Error::Failed("the data directory has no name".to_owned()))?;
    let Some((handle, _)) =
        open_directory_relative(parent, name, FILE_OPEN, None, LIST | WRITE_DAC)
            .map_err(|error| data_unread(paths, "the open of it", error))?
    else {
        return Ok(None);
    };
    match data_directory_reason(paths, &handle) {
        Ok(None) => {}
        Ok(Some((why, origin))) => return Err(data_refusal(paths, &why, &origin, purpose)),
        Err(error) => return Err(data_unread(paths, "a read of it", error)),
    }
    let data = held_directory(handle)?;
    let inspected = inspect_data_directory(paths, purpose, &data)?;
    Ok(Some((data, inspected)))
}

/// Holds the folder above the data directory, made first when it is not there, and makes the data
/// directory beneath it, relative to the held folder, in one call that carries the directory's own
/// protected list, so that it is never there with the list it would take from the folder. The
/// folder is made in one call that carries its protected list, and is then checked like one that
/// was there, on the handle of the call that made it. A data directory that is already there is not trusted for being there: its
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
    make_data_directory_for(paths, Purpose::Install)
}

/// [`make_data_directory`] for a run with this purpose. What the run makes of the data directory's
/// place is held through the handle of the call that made it. A failure after the first of those
/// calls marks what the run made for removal through those handles, and the failure's words say what
/// that did.
fn make_data_directory_for(paths: &Paths, purpose: Purpose) -> Result<DataHolds, Error> {
    let mut made = Made::default();
    match open_data_directory(paths, purpose, &mut made) {
        Ok((held, data, inspected)) => Ok(DataHolds {
            paths: paths.clone(),
            purpose,
            _parent: held,
            made,
            data,
            staging: inspected.staging,
            journal: inspected.journal,
            run: inspected.run,
        }),
        Err(error) => Err(made.after(paths, error)),
    }
}

/// The folder above the data directory and the data directory, each held and checked, and what the
/// directory holds. What this call makes is put in `made` as soon as its call returns, so that a
/// failure of any step after it finds it there.
fn open_data_directory(
    paths: &Paths,
    purpose: Purpose,
    made: &mut Made,
) -> Result<(ffi::Handle, DirHandle, Inspected), Error> {
    let held = match check_data_parent(paths)? {
        Some(held) => held,
        None => match create_data_parent(paths.data_parent())? {
            Some(created) => {
                // The folder is checked on the handle of the call that made it, not opened again
                // by its path: that handle can delete it, and an open that does not share delete
                // would meet it. The copy that this run holds beneath it cannot delete it.
                let copy = created.duplicate(LIST | FILE_ADD_SUBDIRECTORY);
                made.parent = Some(created);
                let held = copy?;
                let stage = remedy::Stage::DataParentMade;
                check_ancestors(paths.data_parent(), remedy::Tree::Data, stage)?;
                check_data_parent_handle(paths, &held, stage)?;
                held
            }
            // A folder that appeared between the look and the call is another program's: the run
            // has changed nothing yet, and it is opened and checked like one that was there.
            None => check_data_parent_at(paths, remedy::Stage::Before)?.ok_or_else(|| {
                // text: make_data_directory-1
                Error::Failed(format!(
                    "something was at {} when this run tried to make it, and the open after that answered not found",
                    paths.data_parent().display()
                ))
            })?,
        },
    };
    let name = paths
        .data
        .file_name()
        // text: make_data_directory-2
        .ok_or_else(|| Error::Failed("the data directory has no name".to_owned()))?;
    let descriptor = data_descriptor()?;
    // A directory that is there is opened with no right to delete it (a running broker may hold it
    // without sharing delete), and a link is opened as the link and refused below. One that is not
    // there is made with the descriptor, through a handle that can mark it for removal.
    let (opened, created) =
        match open_directory_relative(&held, name, FILE_OPEN, None, LIST | WRITE_DAC)? {
            Some(found) => found,
            None => match open_directory_relative(
                &held,
                name,
                FILE_CREATE,
                Some(&descriptor),
                LIST | WRITE_DAC,
            )? {
                Some(made_here) => made_here,
                // Another program made it between the two calls: it is opened, and was not made here.
                None => open_directory_relative(&held, name, FILE_OPEN, None, LIST | WRITE_DAC)?
                    .ok_or_else(|| {
                        // text: make_data_directory-3
                        Error::Failed(format!(
                            "something was at {} when this run tried to make it, and the open after that answered not found",
                            paths.data.display()
                        ))
                    })?,
            },
        };
    // A directory that this run made is held through the handle of the call, which stays in `made`.
    // The handle that the checks and the steps use is a copy that cannot delete it.
    let handle = if created {
        let copy = opened.duplicate(LIST | WRITE_DAC);
        made.directory = Some(opened);
        copy?
    } else {
        opened
    };
    let verdict = data_directory_reason(paths, &handle);
    if created {
        // A directory that this run made and then refuses is taken away again, with the folder
        // above it where the run made that too, so the refusal leaves nothing of the run behind
        // and the removal that undoes the installation finds nothing to meet it with.
        let why = match verdict {
            Ok(None) => None,
            Ok(Some((why, _))) => Some(why),
            Err(error) => Some(format!("a read of it failed ({error})")),
        };
        if let Some(why) = why {
            return Err(refuse_made_data_directory(paths, &why));
        }
    } else {
        match verdict {
            Ok(None) => {}
            Ok(Some((why, origin))) => return Err(data_refusal(paths, &why, &origin, purpose)),
            Err(error) => return Err(data_unread(paths, "a read of it", error)),
        }
    }
    // The reads of the directory's identity, its attributes and its final path are inside the
    // cleanup's reach where this run made it: a failed read leaves nothing of the run behind.
    let data = match held_directory(handle) {
        Ok(data) => data,
        Err(error) if created => {
            return Err(refuse_made_data_directory(
                paths,
                &format!("a read of it failed ({error})"),
            ));
        }
        Err(error) => return Err(error),
    };
    let inspected = if created {
        Inspected {
            manifest: None,
            staging: None,
            journal: None,
            run: None,
            prior: false,
            replacements: Vec::new(),
        }
    } else {
        inspect_data_directory(paths, purpose, &data)?
    };
    Ok((held, data, inspected))
}

/// Makes the folder above the data directory with the protected list, in one call that returns the
/// handle of the folder that it made. The handle is open with the right to delete the folder and
/// shares read and write only, so that nothing renames or deletes the folder while it is held.
/// Returns none where something was there already: a folder that appeared between the look and the
/// call is opened and checked next, and was not made here.
fn create_data_parent(parent: &Path) -> Result<Option<ffi::Handle>, Error> {
    let descriptor = sd::descriptor(SdKind::DataParent, &Principals::default())?;
    // The platform's own form of an absolute path on a drive: `\??\` before the path, which the
    // call takes whole where it has no directory to be relative to.
    let verbatim: Vec<u16> = r"\\?\".encode_utf16().collect();
    let units: Vec<u16> = parent
        .as_os_str()
        .encode_wide()
        .map(|unit| {
            if unit == u16::from(b'/') {
                u16::from(b'\\')
            } else {
                unit
            }
        })
        .collect();
    let rest = units.strip_prefix(verbatim.as_slice()).unwrap_or(&units);
    let name = OsString::from_wide(
        &[r"\??\".encode_utf16().collect::<Vec<u16>>(), rest.to_vec()].concat(),
    );
    Ok(open_directory_at(
        None,
        &name,
        FILE_CREATE,
        Some(&descriptor),
        LIST | FILE_ADD_SUBDIRECTORY,
    )?
    .map(|(handle, _)| handle))
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
        // text: refuse_when_controlled-1
        return Err(Error::Refused(format!(
            "application control already holds rule(s) of this installation's names: {}",
            ours.join(", ")
        )));
    }
    if !effective.is_unconfigured() {
        let named = |keep: &dyn Fn(&policy::Collection) -> bool| -> Vec<&str> {
            effective
                .collections
                .iter()
                .filter(|(_, collection)| keep(collection))
                .map(|(name, _)| name.as_str())
                .collect()
        };
        let enforced = named(&|collection| collection.mode == policy::Mode::Enabled);
        let ruled = named(&|collection| !collection.rules.is_empty());
        // text: refuse_when_controlled-2
        return Err(Error::Refused(remedy::application_control_set(
            &enforced, &ruled,
        )));
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
        // text: refuse_software_restriction-1
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
                // text: refuse_software_restriction-2
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
    match remedy::smart_app_control_refusal(state) {
        // text: refuse_smart_app_control-1
        Some(text) => Err(Error::Refused(text)),
        None => Ok(()),
    }
}

fn refuse_code_integrity() -> Result<(), Error> {
    let listing = |error: &dyn std::fmt::Display| {
        // text: refuse_code_integrity-1
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
            // text: refuse_code_integrity-2
            Error::Refused(format!(
                "the code-integrity policies could not be listed: {error}"
            ))
        })?;
    if !output.status.success() {
        // text: refuse_code_integrity-3
        return Err(Error::Refused(format!(
            "the code-integrity policies could not be listed: {}",
            output.status
        )));
    }
    let listing: serde_json::Value = serde_json::from_slice(&output.stdout).map_err(|error| {
        // text: refuse_code_integrity-4
        Error::Refused(format!(
            "the code-integrity policies could not be read: {error}"
        ))
    })?;
    let policies = listing["Policies"].as_array().ok_or_else(|| {
        // text: refuse_code_integrity-5
        Error::Refused("the code-integrity policies could not be read".to_owned())
    })?;
    match remedy::code_integrity_refusal(policies) {
        // text: refuse_code_integrity-6
        Some(text) => Err(Error::Refused(text)),
        None => Ok(()),
    }
}

/// Finds Git where it installs for every account, refuses when anyone but the system's own class
/// could change it, and records what the policy will name. Git is started with an emptied
/// environment and the system's own working directory.
///
/// # Errors
///
/// Returns [`Error::Refused`] when Git is not where the policy expects it, has an owner or an
/// entry that allows an account outside the system's class to change it, or cannot be run.
pub fn qualify_git() -> Result<GitSet, Error> {
    let dir = git_dir()?;
    let mut images = Vec::new();
    for relative in policy::git_images() {
        let path = dir.join(relative);
        let bytes = fs::read(&path).map_err(|error| {
            // text: qualify_git-1
            Error::Refused(remedy::git_program_not_reached(
                &path.display().to_string(),
                &error,
            ))
        })?;
        if let Some(finding) = acl::changeable_by_others(&path, false)? {
            // text: qualify_git-2
            return Err(Error::Refused(remedy::git_permissions_refusal(
                &path.display().to_string(),
                &finding,
                false,
            )));
        }
        let mut ancestor = path.parent();
        while let Some(parent) = ancestor {
            if parent.parent().is_none() {
                break;
            }
            if let Some(finding) = acl::changeable_by_others(parent, true)? {
                // text: qualify_git-3
                return Err(Error::Refused(remedy::git_permissions_refusal(
                    &parent.display().to_string(),
                    &finding,
                    true,
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
        // text: qualify_git-4
        .map_err(|error| Error::Refused(format!("Git could not be run: {error}")))?;
    // What Git reports is the version the policy is written for: a run that failed, or wrote
    // anything but its one line, is not Git.
    let version = git_version(output.status.success(), &output.stdout).ok_or_else(|| {
        // text: qualify_git-5
        Error::Refused(format!(
            "Git's --version run gave no version that the policy can be written for: it ended with {} and wrote {:?}",
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
        let metadata = fs::symlink_metadata(&source).map_err(|error| {
            // text: stage_payload-1
            Error::Refused(remedy::payload_file_not_reached(
                &source.display().to_string(),
                &error,
            ))
        })?;
        if metadata.file_type().is_symlink()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            // text: stage_payload-2
            return Err(Error::Refused(format!(
                "{} is a reparse point (a link, or a file that a filter serves), not a plain file",
                source.display()
            )));
        }
        let mut handle = OpenOptions::new()
            .read(true)
            .share_mode(0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&source)
            // text: install_stage_payload-1
            .map_err(io_error(format!("opening {}", source.display())))?;
        let mut bytes = Vec::new();
        handle
            .read_to_end(&mut bytes)
            // text: install_stage_payload-2
            .map_err(io_error(format!("reading {}", source.display())))?;
        drop(handle);
        let (mut made, path) = fresh::named_file(staging, "payload", ".exe", SdKind::AdminFile)
            // text: install_stage_payload-3
            .map_err(io_error(format!("staging {name}")))?;
        made.write_all(&bytes)
            .and_then(|()| made.sync_all())
            // text: install_stage_payload-4
            .map_err(io_error(format!("staging {}", path.display())))?;
        drop(made);
        let checked = OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&path)
            // text: install_stage_payload-5
            .map_err(io_error(format!("opening {}", path.display())))?;
        let subject = verify::signer(&checked, &path)?;
        if subject != verify::PUBLISHER {
            // text: stage_payload-3
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
    // text: install_sha256_of-1
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
        // text: keep-1
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

/// Asks the person to type yes after showing the notice, and the account that the broker will
/// serve where there is one: an installation or a repair names it, and a removal enrols none.
///
/// # Errors
///
/// Returns [`Error::Refused`] for any answer but yes.
pub fn confirm(person: Option<&str>, action: &str) -> Result<(), Error> {
    // text: confirm-1
    say(NOTICE);
    // text: confirm-2
    say("");
    if let Some(person) = person {
        // text: confirm-3
        say(&format!("The broker will serve the account {person}."));
    }
    // text: print_confirm-1
    print!("Type yes to {action}: ");
    let _ = io::stdout().flush();
    let mut answer = String::new();
    io::stdin()
        .lock()
        .read_line(&mut answer)
        // text: install_confirm-1
        .map_err(io_error("reading the answer"))?;
    if answer.trim().eq_ignore_ascii_case("yes") {
        Ok(())
    } else {
        // text: confirm-4
        Err(Error::Refused(
            "the answer was not yes, so nothing was changed".to_owned(),
        ))
    }
}

fn person_of(options: &Options) -> Result<String, Error> {
    match &options.person {
        Some(text) => Ok(Sid::parse(text)?.to_text()?),
        None => Ok(token::current_user()?.to_text()?),
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
        // text: install-1
        return Err(Error::Refused(
            "run the setup program as an administrator".to_owned(),
        ));
    }
    let person = person_of(options)?;
    let state = entered(
        paths,
        if repair {
            Purpose::Repair
        } else {
            Purpose::Install
        },
    )?;
    let (manifest, existing) = match (state, repair) {
        (Entry::Fresh, false) => (Manifest::begin(), false),
        (Entry::Fresh, true) => {
            // text: install-2
            return Err(Error::Refused(format!(
                "no manifest says what to repair: the data directory {} is not there, or it holds no manifest",
                paths.data.display()
            )));
        }
        (Entry::Installed(_), false) => {
            // text: install-3
            return Err(Error::Refused(
                "a manifest of this installation is here and says that the installation finished: use repair or remove"
                    .to_owned(),
            ));
        }
        (Entry::Partial(_), false) => {
            // text: install-3-partial
            return Err(Error::Refused(
                "a manifest of this installation is here and says that an installation began and did not finish: use repair or remove"
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
        // text: install-4
        say(&format!(
            "the {} stopped: {failure}",
            if existing { "repair" } else { "installation" }
        ));
        if existing {
            return Err(failure);
        }
        // text: install-5
        say("undoing what was done");
        match remove_at(paths, true, remedy::Stage::Rollback) {
            // text: install-6
            Ok(()) => say("the removal after the failure finished"),
            Err(error) => {
                // text: install-7
                say(&format!(
                    "the removal after the failure also failed: {error}"
                ));
            }
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
    let mut holds = make_data_directory_for(
        &paths,
        if existing {
            Purpose::Repair
        } else {
            Purpose::Install
        },
    )?;
    // Until the first manifest is written a removal finds nothing of what this run made, so a failure
    // of the next two steps takes it away through the handles that made it.
    #[cfg(feature = "testing")]
    if let Err(error) = crate::manifest::forced::failure_at("protect").map_err(Error::Failed) {
        return Err(holds.undo(error));
    }
    if let Err(error) = holds.protect() {
        return Err(holds.undo(error));
    }
    #[cfg(feature = "testing")]
    if let Err(error) = crate::manifest::forced::failure_at("record").map_err(Error::Failed) {
        return Err(holds.undo(error));
    }
    if let Err(error) = run.record(
        ObjectKind::Directory,
        &paths.data.display().to_string(),
        None,
    ) {
        return Err(holds.undo(error));
    }
    // The manifest records the directory now: a removal finds it by the manifest, and the handles
    // that could mark what this run made for removal are closed.
    holds.made = Made::default();
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
            // text: lay_down-1
            other => Error::Failed(format!("making or protecting {what}: {other}")),
        })?;
    }
    drop(holds);
    let channel = Channel::new(&paths.staging);
    // What an earlier run left in staging was checked as the layout names it; it is removed.
    let sweep = |staging: &Path| {
        if let Ok(entries) = fs::read_dir(staging) {
            #[expect(
                clippy::disallowed_methods,
                reason = "a clean-up of what an earlier run left: an entry that cannot be read stays, nothing here says that staging is empty, and this run stages its files under fresh names"
            )]
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

    // text: lay_down-2
    say("reading what is on this computer");
    let (baseline_xml, effective) = if existing {
        let (xml, effective) = channel.effective()?;
        let foreign = effective.foreign_exe_rules();
        if !foreign.is_empty() {
            let ids: Vec<&str> = foreign.iter().map(|rule| rule.id.as_str()).collect();
            // text: lay_down-3
            return Err(Error::Refused(remedy::foreign_rules_refusal(&ids)));
        }
        (xml, effective)
    } else {
        refuse_when_controlled(&channel)?
    };
    let _ = effective;
    let git = qualify_git()?;
    // text: lay_down-4
    say(&format!("Git: {} at {}", git.version, git.dir));
    let staged = stage_payload(&options.payload, &paths.staging)?;
    for file in &staged {
        // text: lay_down-5
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
        // text: lay_down-6
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
        if existing {
            // text: lay_down-7-repair
            say(
                "no earlier-state record was there, so the state that this repair found is recorded in its place",
            );
        } else {
            // text: lay_down-7
            say("the earlier state is recorded");
        }
    }
    inject("directories")?;

    // The program directory and its files.
    let manager = service::manager()?;
    let broker_service = manager.open(SERVICE)?;
    // A repair has no rollback: the broker is said to stay stopped only where a read of its service
    // said stopped. A service that is running is asked to stop and waited for; one that is on its way
    // to either state is waited for (a stop request is refused there); where it does not reach the
    // stopped state within the bound, the run stops before it changes the program directory.
    let mut broker_stopped = false;
    if let Some(service) = &broker_service {
        let end = Instant::now() + Duration::from_secs(60);
        let stopped = remedy::stop_broker(
            || service.status().map(|status| status.broker_state()),
            || service.stop(),
            || {
                if Instant::now() >= end {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(250));
                true
            },
        )
        .map_err(|failure| match failure {
            // A repair has no rollback, so its words say what the refusal was and what the run left;
            // an installation's own failure path says what is undone.
            remedy::StopFailure::Refused(error, last) if existing => {
                // text: lay_down-8
                Error::Failed(remedy::broker_stop_refused(&error.to_string(), last))
            }
            remedy::StopFailure::Refused(error, _) | remedy::StopFailure::Read(error) => {
                Error::from(error)
            }
        })?;
        if !stopped {
            // text: lay_down-9
            return Err(Error::Failed(remedy::broker_not_stopped(existing)));
        }
        broker_stopped = true;
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
    let after = if existing {
        remedy::Stage::AfterRepair { broker_stopped }
    } else {
        remedy::Stage::After
    };
    check_program_parents(&paths, after)?;
    fresh::directory_all(&paths.program, SdKind::AdminDir, &readable)
        // text: install_lay_down-1
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
    if !empty_config
        .try_exists()
        // text: install_lay_down-4
        .map_err(io_error(format!("looking at {}", empty_config.display())))?
    {
        fresh::file_at(&empty_config, SdKind::ProgramFile, true)
            // text: install_lay_down-2
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
            // text: install_lay_down-3
            .map_err(io_error(format!("installing {}", file.name)))?;
        if sha256_of(&target)? != file.sha256 {
            // text: lay_down-10
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
        let sid = match account::find(name)? {
            Some(sid) if existing => sid,
            _ => {
                run.record(ObjectKind::Account, name, None)?;
                account::create(name)?
            }
        };
        let sid_text = sid.to_text()?;
        run.record(ObjectKind::Account, name, Some(&sid_text))?;
        run.record(ObjectKind::Right, &format!("{name}:deny-sign-in"), None)?;
        account::grant_rights(&sid, &account::DENY_RIGHTS)?;
        run.record(
            ObjectKind::RegistryValue,
            &format!("SpecialAccounts\\{name}"),
            None,
        )?;
        account::hide_from_sign_in(name)?;
        // text: lay_down-11
        say(&format!(
            "account {name} ({}) refused sign-in at the screen, by Remote Desktop, as a batch job and as a service, and hidden from the sign-in screen",
            sid_text
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
        // text: lay_down-12
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
        // text: lay_down-13
        say(
            "the Application Identity service is already running, so the policy is written and the platform's report of it is awaited",
        );
    } else {
        let before_start = applocker::newest_record(&paths.staging, &log_env, within(QUERY_BOUND))?;
        Identity(&appid).start()?;
        let first_deadline = within(FIRST_APPLIED_BOUND);
        inject("appid")?;
        // text: lay_down-14
        say(messages::APPLICATION_CONTROL_STARTING);
        let (waited, _) = wait_for_applied(
            before_start,
            first_deadline,
            "the Application Identity service's first \"policy applied\" event",
            &paths.staging,
            &log_env,
        )?;
        // text: lay_down-15
        say(&format!(
            "application control has started: this run saw the platform's report {:.0} s after it started the service",
            waited.as_secs_f32()
        ));
    }

    // The policy, and the platform's next event that says it applied it.
    let wanted = Policy::installed(&sids[0].to_text()?, &sids[1].to_text()?);
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
    // text: lay_down-16
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
    // text: lay_down-17
    say("the platform reports that it applied a policy after the write");
    let (after_xml, after) = channel.effective()?;
    let _ = after_xml;
    let differences = after.differences(&wanted);
    if !differences.is_empty() {
        // text: lay_down-18
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
    // text: lay_down-19
    say("the broker is running");
    inject("broker")?;
    let mut session = open_session()?;
    cycle.prove(&mut session)?;
    run.manifest.state = InstallState::Installed;
    run.manifest.save(&paths.manifest)?;
    // text: lay_down-20
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
                // text: prove-1
                return Err(Error::Failed(format!(
                    "by the installation's count, which began before it started the broker's service, the start-up proof's cycle of {} seconds had less than {} seconds left, so the proof for {class:?} was not asked",
                    self.bound.as_secs(),
                    self.margin.as_secs()
                )));
            }
            session.set_deadline(Some(deadline));
            let response = ask(session, &Request::Prove { class })?;
            if Instant::now() > deadline {
                // text: prove-2
                return Err(Error::Failed(format!(
                    "the answer to the proof for {class:?} was read after the installation's count of the start-up cycle ({} seconds from before the broker's service started) had ended, so it is not taken",
                    self.bound.as_secs()
                )));
            }
            match response {
                Response::Proof {
                    ready: true,
                    detail,
                    // text: prove-3
                } => say(&detail),
                Response::Proof {
                    ready: false,
                    detail,
                } => {
                    // text: prove-4
                    return Err(Error::Failed(format!("the proof failed: {detail}")));
                }
                other => {
                    // text: prove-5
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
        // text: wait_for_applied-1
        Error::Failed(format!(
            "the installation did not find {what} in the application-control log within {} seconds",
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
        // text: open_session-1
        .ok_or_else(|| Error::Failed("the broker's service does not exist".to_owned()))?;
    let status = service.status()?;
    if !status.running() {
        // text: open_session-2
        return Err(Error::Failed(
            "the broker's service is not running".to_owned(),
        ));
    }
    // The process is held from here until the pipe's server is compared with it, so that its number
    // cannot be given to another process in between. It is the service's own process only if the
    // service still runs under that number now that it is held.
    let held = pipe::ServerProcess::open(status.pid)?;
    let again = service.status()?;
    if !again.running() || again.pid != status.pid {
        // text: open_session-3
        return Err(Error::Failed(
            "the broker's service changed while the installer connected to it".to_owned(),
        ));
    }
    let mut connection = pipe::connect_held(pipe::Kind::Administrators, &held)?;
    connection.set_deadline(Some(Instant::now() + HELLO_BOUND));
    let said = ask_frames(
        &mut connection,
        &Request::Hello {
            version: frame::VERSION,
        },
    )
    // text: open_session-4
    .map_err(|failure| Error::Failed(remedy::hello_failure(&failure)))?;
    match said {
        Response::Hello { .. } => {
            // The caller sets the deadline of what it asks next.
            connection.set_deadline(None);
            Ok(connection)
        }
        // text: open_session-5
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
    // text: ask-1
    ask_frames(connection, request).map_err(|error| Error::Failed(error.to_string()))
}

/// [`ask`] with the frame's own error, for a caller that tells a deadline from another failure.
fn ask_frames(
    connection: &mut pipe::Connection,
    request: &Request,
) -> Result<Response, frame::FrameError> {
    frame::write(connection, request)?;
    frame::read(connection)
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
    remove_at(paths, quiet_when_empty, remedy::Stage::Before)
}

/// [`remove`] with the stage of the run that reads the folders above the trees, so that a refusal
/// says only what is so of the run's changes: a removal that undoes a failed installation has
/// changed nothing itself, and what the installation made is still there.
fn remove_at(paths: &Paths, quiet_when_empty: bool, stage: remedy::Stage) -> Result<(), Error> {
    if !token::current_is_administrator()? {
        // text: remove_at-1
        return Err(Error::Refused(
            "run the setup program as an administrator".to_owned(),
        ));
    }
    // The data directory is opened by handle, checked and read here, in this run, and the removal
    // acts on it and on what it holds only through what this inspection approved: a path that no
    // check opened is never read for a manifest and never deleted from. The handles are closed
    // before anything is deleted.
    check_shape(paths, stage)?;
    let mut seen = records::Seen::default();
    let mut approved = records::Approved::default();
    let found = match check_data_parent_at(paths, stage)? {
        Some(parent) => match inspect_existing_data(paths, &parent, Purpose::Remove)? {
            Some((_, inspected)) => {
                seen.journal = inspected.journal.is_some();
                seen.run = inspected.run.is_some();
                approved = records::Approved {
                    prior: inspected.prior,
                    staging: inspected.staging.is_some(),
                    replacements: inspected.replacements,
                };
                match inspected.manifest {
                    Some(manifest) => records::Inspection::Recorded(manifest),
                    None => records::Inspection::Empty,
                }
            }
            None => records::Inspection::Absent,
        },
        None => records::Inspection::Absent,
    };
    #[cfg(feature = "testing")]
    testing::after_the_removal_inspection();
    // The program directory is read on a held handle before the removal deletes anything in it.
    let program_checked = check_program_directory(
        paths,
        matches!(found, records::Inspection::Recorded(_)),
        stage,
    )?;
    if matches!(found, records::Inspection::Recorded(_)) {
        refuse_while_unfinished(paths)?;
    }
    let manifest = match records::begin(
        found,
        &|| records::look(&paths.data),
        quiet_when_empty,
        &paths.data,
    ) {
        // text: remove_at-2
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
                // text: remove_at-3
                say("the empty data directory is not there now");
                return Ok(());
            }
            // text: remove_at-4
            return Err(Error::Failed(format!(
                "the data directory stays: {}. {}",
                stayed.join("; "),
                records::next_step(
                    &records::look(&paths.manifest),
                    &records::held_in(&paths.data)
                )
            )));
        }
        records::Begin::Remove(manifest) => manifest,
    };
    // A record that was approved and cannot be loaded is not used, and the last words say so.
    let (prior, prior_error) = match approved.prior_record(|| Prior::load(&paths.prior)) {
        Ok(prior) => (prior, None),
        Err(error) => (None, Some(error.to_string())),
    };
    // A removal that took `staging` and could not delete the manifest leaves a manifest with no
    // `staging`, and the channel makes its temporary directory there. Where the inspection did not
    // open `staging`, the removal makes it itself, empty, with a creation that fails when anything is
    // there, and it goes with the records; what appeared since the inspection is left and named,
    // before anything is changed.
    if !approved.staging {
        match fresh::directory_at(&paths.staging, SdKind::AdminDir, &Principals::default()) {
            Ok(()) => approved.staging = true,
            Err(error) if error.raw_os_error() == Some(ERROR_ALREADY_EXISTS as i32) => {
                // text: remove_at-5
                return Err(Error::Refused(format!(
                    "{}. Nothing was removed. Run the removal again: it checks the directory first, and says what to do about it if it is not the installation's own.",
                    records::not_there_at_the_inspection(&paths.staging)
                )));
            }
            // text: install_remove_at-1
            Err(error) => return Err(io_error("making the staging directory")(error)),
        }
    }
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
            let answer = ask(&mut connection, &Request::Maintenance { on: true })?;
            Ok((connection, answer))
        }) {
            Ok((connection, answer)) => {
                match answer {
                    Response::Done {} => {
                        // text: remove_at-6
                        say("the broker is in its maintenance state");
                    }
                    Response::Refused { reason, detail } => {
                        // text: remove_at-7-refused
                        say(&format!(
                            "the broker refused the request for its maintenance state ({reason:?}: {detail})"
                        ));
                    }
                    other => {
                        // text: remove_at-7-answer
                        say(&format!(
                            "the broker answered the request for its maintenance state with {other:?}, not that it was carried out"
                        ));
                    }
                }
                // Whatever the broker answered, the connection stays the session: the release is asked
                // of the broker below, and what it answers there is a failure of the removal.
                session = Some(connection);
            }
            // text: remove_at-7
            Err(error) => say(&format!(
                "the broker's maintenance state could not be set ({error}), so the release is not proved through the broker"
            )),
        }
    }

    // (2) the policy: our rules go; a rule that the installation did not make keeps the allow-all rule beside it.
    let has_rules = manifest.of_kind(ObjectKind::PolicyRule).next().is_some();
    if has_rules {
        keep(
            (|| -> Result<(), Error> {
                let (xml, effective) = channel.effective()?;
                let (_, kept) = effective.without_ours();
                if let Some(shared) = shared_rules(&effective) {
                    if kept {
                        // text: remove_at-8
                        say(&format!(
                            "{}, so the allow-all rule and the collection's mode stay in force beside it",
                            shared.words()
                        ));
                    } else {
                        // text: remove_at-8-without-allow-all
                        say(&format!(
                            "{}, and the installation's allow-all rule is not there, so the collection's mode stays as it is",
                            shared.words()
                        ));
                    }
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
                // Where the earlier-state record holds an executable collection with no rule and a
                // mode, a collection that holds only what the installation set (its mode, and no
                // rule but its own) is written back as the record holds it; one that holds more is
                // written as it is found, without the installation's rules. A record that was not
                // read gives no mode, so the collection is written as it is found.
                let recorded = recorded_of(prior.as_ref(), prior_error.as_deref());
                let present = effective.exe_mode().unwrap_or(policy::Mode::NotConfigured);
                let restore =
                    policy::restore_for(&recorded, present, shared_rules(&effective).is_some());
                let emptied = restore.emptied();
                let stripped = policy::strip(&xml, drop, emptied);
                // text: remove_at-9
                let stripped = stripped.map_err(|error| Error::Failed(error.to_string()))?;
                channel.set(&stripped)?;
                match &restore {
                    policy::Restore::Unread(why) => {
                        // Only the rules that this step takes out are named, and the mode that the
                        // collection keeps. A record that was loaded still gives the fields that
                        // were read from it; one that was not loaded gives none.
                        let taken = if kept {
                            "the installation's two deny rules"
                        } else {
                            "the installation's rules"
                        };
                        let fields = if prior.is_some() {
                            "The record itself was read, so the Application Identity service's start value and whether it was running are used from it below, where the removal's steps for them apply."
                        } else {
                            "No field of the record was read, so none is used from it."
                        };
                        // text: remove_at-10-unread
                        say(&format!(
                            "the earlier state's policy could not be read ({why}), so no mode is written back from it: the policy is written without {taken}, and the executable collection is left as it is found, with the mode {present:?}. A rule that is added to it later takes effect in that mode. {fields}"
                        ));
                    }
                    policy::Restore::Record(mode) => {
                        // text: remove_at-10-record
                        say(&format!(
                            "the policy is written without the installation's rules, and the executable collection is written as the earlier-state record holds it: no rule, and the mode {mode:?}"
                        ));
                    }
                    policy::Restore::Same(mode) => {
                        // text: remove_at-10-same
                        say(&format!(
                            "the executable collection already has the mode {mode:?} that the earlier-state record holds, so it is written as it is found, without the installation's rules"
                        ));
                    }
                    policy::Restore::Stays { present, recorded } => {
                        // text: remove_at-10-stays
                        say(&format!(
                            "the executable collection has the mode {present:?}, which is neither the mode that the installation sets nor the earlier-state record's {recorded:?}, so it is written as it is found, without the installation's rules, and the mode {present:?} stays"
                        ));
                    }
                    // The record holds no empty executable collection with a mode, and no rule of
                    // anyone else's keeps the collection: it is written as not configured. A mode
                    // that is neither the installation's nor not configured (audit only) was set
                    // after the installation, and the write replaces it.
                    policy::Restore::NotConfigured => {
                        if shared_rules(&effective).is_none() && present == policy::Mode::AuditOnly
                        {
                            // text: remove_at-10-not-configured
                            say(&format!(
                                "the executable collection has the mode {present:?}, which the installation did not set, and the earlier-state record holds no empty executable collection with a mode, so it is written as not configured: the mode {present:?} does not stay"
                            ));
                        }
                    }
                }
                if kept {
                    // text: remove_at-10-kept
                    say(
                        "the policy is written without the installation's two deny rules, and its allow-all rule and the collection's mode stay",
                    );
                } else {
                    // text: remove_at-10
                    say("the policy is written without the installation's rules");
                }
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
                    // text: remove_at-11
                    Error::Failed("the Application Identity service is missing".to_owned())
                })?;
                let (current, _) = appid.configuration()?;
                let set_by_us = object.detail.as_deref() == Some(&format!("start={current}"));
                if set_by_us && current != prior.appid_start_type {
                    if let Some(key) = registry::open(APPID_KEY)? {
                        key.set_dword("Start", prior.appid_start_type)?;
                        // text: remove_at-12
                        say(&format!(
                            "the Application Identity service's start value in the registry is back to {}",
                            prior.appid_start_type
                        ));
                    }
                } else {
                    // text: remove_at-13
                    say(&remedy::appid_start_type_left(
                        current,
                        object.detail.as_deref(),
                        prior.appid_start_type,
                    ));
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
                    // text: remove_at-14
                }) => say(&detail),
                Ok(Response::Proof {
                    ready: false,
                    detail,
                }) => {
                    keep(
                        // text: remove_at-15
                        Err(Error::Failed(detail)),
                        "proving the release",
                        &mut failures,
                    );
                }
                Ok(other) => keep(
                    // text: remove_at-16
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
                    // text: remove_at-17
                    say("the Application Identity service is stopped as it was");
                }
                Ok(())
            })(),
            "deciding whether the Application Identity service stops",
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
                    // text: remove_at-18
                    say(
                        "the broker's service is already marked for deletion: the service manager removes it once it is stopped and no program holds it open",
                    );
                } else {
                    service.delete()?;
                    // text: remove_at-19
                    say(
                        "the broker's service is marked for deletion: the service manager removes it once it is stopped and no program holds it open",
                    );
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
        let recorded = object.detail.clone();
        keep(
            (|| -> Result<(), Error> {
                // The account is looked up by the identifier that the manifest records, so an
                // account that has been renamed is found; only where the manifest records none is
                // it looked up by its name. A lookup that failed ends this step before anything of
                // the account is changed: only a lookup that answered "no such account" goes on
                // without a right to take away.
                let found = match &recorded {
                    Some(id) => account::find_by_id(id)?,
                    None => account::find(&name)?.map(|sid| (sid, name.clone())),
                };
                if let Some((sid, _)) = &found {
                    account::revoke_all_rights(sid)?;
                    account::delete_profile(sid)?;
                }
                account::unhide_from_sign_in(&name)?;
                match (&found, &recorded) {
                    (Some((_, current)), _) => account::delete(current)?,
                    (None, None) => account::delete(&name)?,
                    (None, Some(_)) => {}
                }
                match (&found, &recorded) {
                    (Some((_, current)), _) if *current == name => {
                        // text: remove_at-20
                        say(&format!("account {name} is removed with its rights"));
                    }
                    (Some((_, current)), _) => {
                        // text: remove_at-20-renamed
                        say(&format!(
                            "account {name} is named {current} now, and is removed with its rights"
                        ));
                    }
                    (None, None) => {
                        // text: remove_at-20-not-found
                        say(&format!(
                            "account {name} is not found by its name, and the manifest records no identifier for it, so its rights were not taken away"
                        ));
                    }
                    (None, Some(_)) => {
                        // text: remove_at-20-no-identifier
                        say(&format!(
                            "no account has the identifier that the manifest records for {name}, so no rights were taken away"
                        ));
                    }
                }
                Ok(())
            })(),
            "removing an account",
            &mut failures,
        );
    }
    if program_checked {
        keep(
            // text: install_remove_at-2
            fs::remove_dir_all(&paths.program).map_err(io_error("removing the program directory")),
            "removing the program directory",
            &mut failures,
        );
        if let Some(parent) = paths.program.parent() {
            let _ = fs::remove_dir(parent);
        }
    } else if let Some(text) = records::looked_at_again(&paths.program) {
        // It was not there when the removal checked, so no check opened it: nothing is deleted.
        failures.push(text);
    }
    // The journal's files and the empty `run` and `journal` directories go where the inspection
    // opened and approved them, and nowhere else. Unfinished work was refused before the removal
    // began; what a journal file still holds now is finished or made nothing.
    for stayed in records::finish_journal_and_run(&paths.journal, &paths.run, seen) {
        // text: remove_at-21
        say(&format!("the journal or the private roots stay: {stayed}"));
        failures.push(format!(
            "removing the journal or the private roots: {stayed}"
        ));
    }
    if let Some(prior) = &prior {
        match residue(prior, paths, &manifest) {
            Ok(Residue {
                left,
                shared,
                unread,
                stays,
                accounts,
            }) if left.is_empty() => {
                if let Some(why) = &unread {
                    // text: remove_at-22-unread
                    say(&format!(
                        "the earlier state's policy could not be read ({why}), so no mode was written back from it and the policy was not compared with it"
                    ));
                }
                if let Some(shared) = shared {
                    // text: remove_at-22-present
                    say(&format!(
                        "the policy shows no difference from the present policy without the installation's two deny rules ({}, so the earlier-state record is not the comparison{}); {accounts}, the sign-in list has no value for either name, the broker's service is not there or is marked for deletion, and the program directory is not there",
                        shared.words(),
                        if shared.allow_all_stays {
                            "; the allow-all rule stays"
                        } else {
                            ""
                        }
                    ));
                } else if let Some(stays) = stays {
                    // text: remove_at-22-stays
                    say(&format!(
                        "the policy shows no difference from the earlier-state record except the executable collection's mode: the collection has the mode {:?}, which stays, and the record held {:?}; {accounts}, the sign-in list has no value for either name, the broker's service is not there or is marked for deletion, and the program directory is not there",
                        stays.present, stays.recorded
                    ));
                } else if unread.is_some() {
                    // text: remove_at-22-unread-rules
                    say(&format!(
                        "the policy holds no rule of the installation; {accounts}, the sign-in list has no value for either name, the broker's service is not there or is marked for deletion, and the program directory is not there"
                    ));
                } else {
                    // text: remove_at-22
                    say(&format!(
                        "the policy shows no difference from the earlier-state record; {accounts}, the sign-in list has no value for either name, the broker's service is not there or is marked for deletion, and the program directory is not there"
                    ));
                }
            }
            Ok(Residue { left, .. }) => {
                for line in &left {
                    // text: remove_at-23
                    say(&format!("the check after the removal found: {line}"));
                }
                failures.push(format!(
                    "the check after the removal found: {}",
                    left.join("; ")
                ));
            }
            Err(error) => failures.push(format!("checking the earlier state: {error}")),
        }
    }
    // A record that the inspection did not approve was not used: the Application Identity service
    // keeps what the installation gave it, and the last words say so.
    let unread_prior = format!(
        "{}{}",
        records::unread_prior(approved.prior, &records::look(&paths.prior)),
        prior_error
            .as_deref()
            .map(records::unloaded_prior)
            .unwrap_or_default()
    );
    if failures.is_empty() {
        // The records go last: a failed removal can be run again from them.
        let stayed = remove_approved_records(paths, &approved);
        if stayed.is_empty() {
            // text: remove_at-24
            say(&format!(
                "the removal ended without a failure and its records are deleted{unread_prior}"
            ));
            Ok(())
        } else {
            // While the manifest stays, the removal runs again whole and reads it. Without it,
            // an empty directory is finished by the next removal, and anything else in it is for
            // the person to remove.
            let next = records::next_step(
                &records::look(&paths.manifest),
                &records::held_in(&paths.data),
            );
            // text: remove_at-25
            Err(Error::Failed(format!(
                "the removal's steps ended without a failure, but the removal of its records left: {}. {next}{unread_prior}",
                stayed.join("; ")
            )))
        }
    } else {
        // text: remove_at-26
        Err(Error::Failed(format!(
            "the removal did not finish and its records are kept: {}{unread_prior}",
            failures.join("; ")
        )))
    }
}

/// Removes the installation's own records, last of all, and then the data directory and, when it is
/// empty, the folder above it. The records go in the order [`records::remove`] gives: the manifest
/// last, so that a removal that stayed anywhere is run again from it. Returns each thing that could
/// not be removed, with the reason; nothing is returned when everything is gone. It approves every
/// record that is there now, for a caller that has inspected nothing; the removal approves what its
/// own inspection opened.
#[cfg(feature = "testing")]
pub fn remove_records(paths: &Paths) -> Vec<String> {
    remove_approved_records(paths, &records::Approved::all_that_are_there(&paths.data))
}

/// Removes the records that the removal's own inspection approved: a record that is
/// there now and that it did not see is left and named.
fn remove_approved_records(paths: &Paths, approved: &records::Approved) -> Vec<String> {
    let stayed = records::remove(&Records {
        data: &paths.data,
        manifest: &paths.manifest,
        prior: &paths.prior,
        staging: &paths.staging,
        approved,
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
                    // text: install_refuse_while_unfinished-1
                    entry.map_err(io_error("reading the directory of the private roots"))?;
                found.push(format!(
                    "a private root {}",
                    entry.file_name().to_string_lossy()
                ));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            // text: install_refuse_while_unfinished-2
            return Err(io_error("reading the directory of the private roots")(
                error,
            ));
        }
    }
    match records::look(&paths.journal) {
        records::Look::NotThere => {}
        records::Look::Unread(error) => {
            // text: refuse_while_unfinished-3
            return Err(Error::Failed(format!("reading the journal: {error}")));
        }
        records::Look::There => {
            let unfinished = super::journal::replay(&paths.journal, "")
                // text: refuse_while_unfinished-1
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
    }
    if found.is_empty() {
        Ok(())
    } else {
        // text: refuse_while_unfinished-2
        Err(Error::Refused(format!(
            "work that is not proved done is recorded, so this removal changed nothing: {}",
            found.join("; ")
        )))
    }
}

/// The rules of the executable collection that the installation did not make, by their
/// identifiers, and whether the installation's allow-all rule is in the collection beside them.
pub struct Shared {
    /// The identifiers of the rules that the installation did not make.
    pub ids: Vec<String>,
    /// Whether the allow-all rule is there, and so stays.
    pub allow_all_stays: bool,
}

impl Shared {
    /// Says what is in the collection: the rules, by that and by their identifiers.
    fn words(&self) -> String {
        match self.ids.as_slice() {
            [id] => format!(
                "a rule that the installation did not make, with the identifier {id}, is in the executable collection"
            ),
            ids => format!(
                "rules that the installation did not make, with the identifiers {}, are in the executable collection",
                ids.join(", ")
            ),
        }
    }
}

/// What the earlier-state record gives for the executable collection, from the record that was
/// loaded (or the error that loading it gave).
fn recorded_of(prior: Option<&Prior>, load_error: Option<&str>) -> policy::Recorded {
    match prior {
        Some(prior) => policy::Recorded::of(Policy::parse(&prior.policy_xml)),
        None => policy::Recorded::Unread(match load_error {
            Some(error) => format!("the record could not be loaded: {error}"),
            None => "no record of it was read".to_owned(),
        }),
    }
}

/// The rules in the policy's executable collection that the installation did not make, none where
/// there is no such rule.
fn shared_rules(policy: &Policy) -> Option<Shared> {
    let others = policy.foreign_exe_rules();
    (!others.is_empty()).then(|| Shared {
        ids: others.iter().map(|rule| rule.id.clone()).collect(),
        allow_all_stays: policy.without_ours().1,
    })
}

/// What a check after a removal found, and what it read.
pub struct Residue {
    /// What is left, or could not be read, one line each; empty where every comparison holds.
    pub left: Vec<String>,
    /// The rules that the installation did not make, where the policy was compared with the present
    /// policy less the installation's rules.
    pub shared: Option<Shared>,
    /// Why the earlier-state record's policy was not read, where it does not parse: the policy was
    /// then not compared with it.
    pub unread: Option<String>,
    /// The mode of the executable collection where it stays: it is neither the installation's nor
    /// the earlier-state record's, and the comparison allowed for it.
    pub stays: Option<policy::Stays>,
    /// What the check read of the two accounts where nothing of them was found: for each, that no
    /// account has the identifier that the manifest records, or the name where it records none.
    pub accounts: String,
}

/// What the machine shows of the installation after a removal, and what the policy was compared
/// with. The policy is compared with the earlier-state record, or, where a rule that the
/// installation did not make has joined the executable collection, with the present policy without
/// the installation's rules (the second part is the rules that are there then). Each account is
/// looked up by the identifier that the manifest records for it, or by its name where the manifest
/// records none; the sign-in list, the broker's service and the program directory are looked at too.
/// All are compared with their not being there. An empty list means that each comparison holds. The data directory is not counted: it holds the records this check reads, and
/// goes last.
///
/// # Errors
///
/// Returns the failure of a call that could not look.
pub fn residue(prior: &Prior, paths: &Paths, manifest: &Manifest) -> Result<Residue, Error> {
    let mut left = Vec::new();
    let (_, effective) = Channel::new(&paths.staging).effective()?;
    // The record's policy is read here as the removal read it. Where it does not parse, nothing is
    // compared with it: the present policy is only looked at for the installation's rules, and the
    // lines say so.
    let baseline = Policy::parse(&prior.policy_xml);
    let (baseline, unread) = match baseline {
        Ok(baseline) => (Some(baseline), None),
        Err(error) => (None, Some(error.to_string())),
    };
    // Where a rule that the installation did not make has since joined the executable collection, the
    // removal keeps the allow-all rule, where it is there, and the collection's mode beside it on
    // purpose; everything else of ours is gone.
    let shared = shared_rules(&effective);
    let mut stays = None;
    match (&shared, baseline) {
        (Some(_), _) => left.extend(effective.differences(&effective.without_ours().0)),
        (None, Some(baseline)) => {
            // A mode that is neither the installation's nor the record's stays, so it is not a
            // difference from the record that keeps the removal from finishing: the lines say it.
            let (expected, allowed) = policy::expected_after(&baseline, &effective);
            stays = allowed;
            left.extend(effective.differences(&expected));
        }
        (None, None) => {
            if effective.holds_our_rules() {
                left.push("the policy still holds a rule of the installation".to_owned());
            }
        }
    }
    let mut read = Vec::new();
    for name in [CHECKOUT, CONNECT] {
        // Each account is looked up by the identifier that the manifest records for it, so an
        // account that has been renamed is found; where the manifest records none, by its name.
        let recorded = manifest
            .find(ObjectKind::Account, name)
            .and_then(|object| object.detail.as_deref());
        match recorded {
            Some(id) => match account::find_by_id(id) {
                Ok(Some((_, now))) if now == name => {
                    left.push(format!("the account {name} is still there"));
                }
                Ok(Some((_, now))) => {
                    left.push(format!("the account {name} is still there, named {now}"));
                }
                Ok(None) => read.push(format!(
                    "no account has the identifier that the manifest records for {name}"
                )),
                Err(error) => left.push(format!(
                    "a lookup of the account that has the identifier recorded for {name} failed ({error}), so whether it is gone is not known"
                )),
            },
            None => match account::find(name) {
                Ok(Some(_)) => left.push(format!("the account {name} is still there")),
                Ok(None) => read.push(format!(
                    "no account has the name {name}, and the manifest records no identifier for it"
                )),
                Err(error) => left.push(format!(
                    "a lookup of the account {name} failed ({error}), so whether it is gone is not known"
                )),
            },
        }
        if account::hidden_from_sign_in(name)? {
            left.push(format!("the sign-in list still has a value for {name}"));
        }
    }
    if let Some(service) = service::manager()?.open(SERVICE)?
        && !service.marked_for_deletion()?
    {
        left.push("the broker's service is still there".to_owned());
    }
    match records::look(&paths.program) {
        records::Look::There => left.push(format!("{} is there", paths.program.display())),
        records::Look::NotThere => {}
        records::Look::Unread(error) => left.push(format!(
            "a look at {} failed ({error}), so whether it is gone is not known",
            paths.program.display()
        )),
    }
    Ok(Residue {
        left,
        shared,
        unread,
        stays,
        accounts: read.join("; "),
    })
}
