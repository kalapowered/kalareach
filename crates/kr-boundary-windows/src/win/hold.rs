//! The tree hold: the handles the broker keeps on a project's directories and on its repository's
//! configuration for as long as an invocation works on it.
//!
//! The chain handles (H1) are every directory from the volume's root down to the tree's root and
//! then the repository's `.git`, each opened relative to the one above it and shared for reading
//! and writing but not for delete: another open that asks for delete access, which a rename or a
//! removal needs, is refused with a sharing violation. The configuration handle (H2) is shared for
//! reading only, so nothing can write, rename or delete `config` while it is held; the broker reads
//! the configuration's bytes from that handle, so they are those of the file that stays.
//!
//! The holds do not stop the creation of a new name inside a held directory, and they do not stop
//! Git's own writes to other files. The pre-resume check and the end check look for what they leave.
//!
//! The directories are opened as the system, so each is first read for the person's own right to
//! read it: nothing is held for a person that the person could not open.

#![allow(unsafe_code)]

use std::fs::File;
use std::io::Read as _;
use std::os::windows::io::BorrowedHandle;
use std::path::Path;
use std::ptr::{null, null_mut};

use sha2::{Digest, Sha256};
use windows_sys::Wdk::Storage::FileSystem::FILE_OPEN;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
    FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_STANDARD_INFO, FileAttributeTagInfo, FileStandardInfo,
    GetFinalPathNameByHandleW, OPEN_EXISTING, QueryDosDeviceW, VOLUME_NAME_DOS,
};

use crate::filekey::FileKey;
use crate::frame::invocation::{MAX_DETAIL_BYTES, RefusedKind};
use crate::journal::rows::{Row, SnapshotKind};
use crate::local_path;
use crate::refusal::Refusal;
use crate::slot::TreeIdentity;

use super::admission::{
    attributes_refusal, chain_paths, cut_start, is_cloud_tag, reparse_refusal, spelled,
};
use super::client::ClientIdentity;
use super::ffi::{self, Handle, wide_path};
use super::listing::{self, Failure, RepositoryListing};
use super::rights::{Right, Sd};
use super::walk::{AnchorRefusal, DirHandle, LIST, Lost, NotFolder, final_path, key_of, query};

/// The most UTF-16 units of text that the platform answers for where a drive letter leads.
const MAX_TARGET_UNITS: usize = 32_768;

/// The most bytes the repository's `config` may hold; a larger file is refused before it is read.
pub const MAX_CONFIG_BYTES: u64 = 262_144;

/// The rule of a refusal for a text that is not a path on a local drive.
pub const RULE_FOLDER_FORM: &str = "hold-folder-form";
/// The rule of a refusal for a folder on the way that carries a volume mounted in it.
pub const RULE_FOLDER_MOUNT: &str = "hold-folder-mount";
/// The rule of a refusal for a folder that was not found.
pub const RULE_FOLDER_MISSING: &str = "hold-folder-missing";
/// The rule of a refusal for a folder that is a link.
pub const RULE_FOLDER_LINK: &str = "hold-folder-link";
/// The rule of a refusal for a folder that moved or changed while it was opened.
pub const RULE_FOLDER_CHANGED: &str = "hold-folder-changed";
/// The rule of a refusal for an object the person cannot read.
pub const RULE_PERSON: &str = "hold-person";
/// The rule of a refusal for a project with no `.git` folder.
pub const RULE_NO_GIT: &str = "hold-no-git";
/// The rule of a refusal for a repository with no `config` file.
pub const RULE_NO_CONFIG: &str = "hold-no-config";
/// The repository's `.git` holds submodules.
pub const RULE_MODULES: &str = "hold-modules";
/// The rule of a refusal for a `config` that has more than one name.
pub const RULE_CONFIG_LINKS: &str = "hold-config-links";
/// The rule of a refusal for a `config` that another program has open for writing.
pub const RULE_CONFIG_BUSY: &str = "hold-config-busy";
/// The rule of a refusal for a `config` over [`MAX_CONFIG_BYTES`].
pub const RULE_CONFIG_SIZE: &str = "config-too-large";
/// The rule of a refusal for a call that the platform failed.
pub const RULE_HOLD_FAILED: &str = "hold-failed";
/// The rule of a refusal for a name that must be absent from the Git folder and is there.
pub const RULE_ABSENT_NAME: &str = "hold-absent-name";
/// The rule of a refusal for a hooks folder or an attributes file over a bound of the listing.
pub const RULE_LISTING_BOUND: &str = "hooks-too-large";

/// The start of the reply when a name that must be absent is in the Git folder; the name follows
/// after a colon.
// text: ABSENT_NAME_WORDS
pub const ABSENT_NAME_WORDS: &str =
    "the repository holds a file or folder that the broker does not accept";

/// The reply when the hooks folder or the attributes file is over a bound of the listing.
// text: LISTING_BOUND_WORDS
pub const LISTING_BOUND_WORDS: &str = "the hooks folder or info attributes file is larger than the broker reads (at most 256 objects in all, 4 levels of folders, 128 entries in the hooks folder, 255 bytes for a name, 1 MiB for a file)";

/// The reply when the text is not a path on a local drive, or names a drive that is not a local disk.
// text: FOLDER_FORM_WORDS
pub const FOLDER_FORM_WORDS: &str =
    "name the project folder by a path on a local drive, such as C:\\Users\\you\\project";

/// The reply when a folder on the way to the project carries a volume mounted in it.
// text: MOUNT_POINT_WORDS
pub const MOUNT_POINT_WORDS: &str = "a folder on the way to the project is a volume mounted in a folder, which the broker does not follow; give the volume a drive letter and name the project by it";

/// The reply when the folder is not there.
// text: FOLDER_MISSING_WORDS
pub const FOLDER_MISSING_WORDS: &str = "the project folder was not found";

/// The reply when the folder is a link.
// text: FOLDER_LINK_WORDS
pub const FOLDER_LINK_WORDS: &str =
    "the project folder is a link; name the folder the link points to";

/// The reply when the folder moved while the broker opened it.
// text: FOLDER_CHANGED_WORDS
pub const FOLDER_CHANGED_WORDS: &str = "the project folder changed while the broker opened it";

/// The start of the reply when the person's own account may not read an object; the path follows
/// after a colon.
// text: PERSON_WORDS
pub const PERSON_WORDS: &str = "your account cannot read this path";

/// The reply when the project has no `.git` folder.
// text: NO_GIT_WORDS
pub const NO_GIT_WORDS: &str =
    "the project folder has no .git folder; a .git file or link in its place is not accepted";

/// The reply when the repository has submodules: not opened through the boundary.
// text: MODULES_WORDS
pub const MODULES_WORDS: &str = "this repository has submodules, and the broker does not guard their own Git settings and hooks, so it does not open it; use Git on it outside the broker, or name a project without submodules";

/// The reply when the repository has no `config`.
// text: NO_CONFIG_WORDS
pub const NO_CONFIG_WORDS: &str = "the repository has no config file in its .git folder";

/// The reply when the `config` is not one ordinary file with one name.
// text: CONFIG_LINKS_WORDS
pub const CONFIG_LINKS_WORDS: &str =
    "the repository's config is not one ordinary file with one name";

/// The reply when another program has the `config` open for writing.
// text: CONFIG_BUSY_WORDS
pub const CONFIG_BUSY_WORDS: &str = "another program has the repository's config open or is replacing it; try again when it has closed it";

/// The reply when the `config` is over the bound.
// text: CONFIG_SIZE_WORDS
pub const CONFIG_SIZE_WORDS: &str =
    "the repository's config is larger than 256 KiB (262,144 bytes)";

/// The start of the reply when a call of the platform failed; its own words follow after a colon.
// text: HOLD_FAILED_WORDS
pub const HOLD_FAILED_WORDS: &str = "the broker could not hold the project folder";

/// What the broker reads of `config` and keeps: the open handle, and the bytes with their digest.
#[derive(Debug)]
pub struct ConfigSnapshot {
    /// The file's handle, shared for reading only, held until the invocation has ended.
    pub handle: Handle,
    /// The SHA-256 of the bytes.
    pub digest: [u8; 32],
    /// The bytes, read from the handle.
    pub bytes: Vec<u8>,
    /// The file's identity.
    pub identity: FileKey,
    /// The file's number of names, which is one.
    pub link_count: u32,
}

/// A project's held tree.
#[derive(Debug)]
pub struct TreeHold {
    /// Every directory from the volume's root down to the tree's root, the root first.
    pub chain: Vec<DirHandle>,
    /// The repository's `.git`.
    pub git_dir: DirHandle,
    /// The repository's `config`.
    pub config: ConfigSnapshot,
    /// The keys of `chain`: what the slot is keyed by.
    pub identity: TreeIdentity,
    /// What the Git folder held, besides `config`, when the tree was held.
    pub listing: RepositoryListing,
    /// The states of an operation in progress that the Git folder held when the tree was held.
    pub states: Vec<String>,
    /// Each listed hook, the attributes file and the exclude file, open for reading and shared for
    /// reading only, so that no account can write, rename or delete one while the tree is held.
    pub listed_files: Vec<Handle>,
    /// The tree's path as the platform spells it now: what the journal records.
    pub path: String,
}

/// What a check found different from what the hold took: the names, sorted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Changed {
    /// The names of the objects that differ, relative to the Git folder; `config` for the
    /// repository's configuration, and the final path of a held folder that changed.
    pub names: Vec<String>,
}

impl TreeHold {
    /// Looks again for the names that must be absent, from the held `.git` folder, immediately
    /// before the operation's process resumes.
    ///
    /// # Errors
    ///
    /// Returns the names that are there now.
    pub fn pre_resume_check(&self) -> Result<(), Changed> {
        let names = listing::present_names(&self.git_dir);
        if names.is_empty() {
            Ok(())
        } else {
            Err(Changed { names })
        }
    }

    /// Compares what the tree holds now with what the hold took, after the operation has ended: the
    /// configuration opened afresh by its path (the same file, one name, the same size and bytes),
    /// each held folder (the same identity and final path), the names that must be absent, a
    /// `modules` folder, a folder that the person's next Git writes into and that is a link now, a
    /// state of an operation that the hold did not find, and the hooks, the attributes file and
    /// the exclude file by name, identity, size and digest. The contents of a state that the hold
    /// found are not compared.
    ///
    /// # Errors
    ///
    /// Returns the names that differ, or that could not be shown to be the same.
    pub fn end_check(&self) -> Result<(), Changed> {
        let mut names = std::collections::BTreeSet::new();
        if !self.config_is_unchanged() {
            names.insert("config".to_owned());
        }
        // A folder that changed is named by its path as the person spells it, from the tree's own
        // path, not by the device path that the held handle reports.
        let paths = chain_paths(&self.path);
        let git_path = format!(r"{}\.git", spelled(&self.path));
        let folders = self.chain.iter().chain(std::iter::once(&self.git_dir));
        for (index, folder) in folders.enumerate() {
            if !folder_is_unchanged(folder) {
                let shown = if index < self.chain.len() {
                    paths.get(index)
                } else {
                    Some(&git_path)
                };
                names.insert(
                    shown
                        .cloned()
                        .unwrap_or_else(|| String::from_utf16_lossy(folder.path())),
                );
            }
        }
        names.extend(listing::present_names(&self.git_dir));
        if listing::modules_present(&self.git_dir) {
            names.insert("modules".to_owned());
        }
        names.extend(listing::linked_folders(&self.git_dir));
        names.extend(
            listing::present_states(&self.git_dir)
                .into_iter()
                .filter(|name| !self.states.contains(name)),
        );
        match listing::take(&self.git_dir) {
            Ok(now) => names.extend(listing::differences(&self.listing, &now)),
            Err(_) => {
                names.insert("hooks".to_owned());
                names.insert(r"info\attributes".to_owned());
                names.insert(r"info\exclude".to_owned());
            }
        }
        if names.is_empty() {
            Ok(())
        } else {
            Err(Changed {
                names: names.into_iter().collect(),
            })
        }
    }

    /// The journal row that records what the hold took: the configuration's digest, the hooks, the
    /// attributes file, the exclude file and the names that must be absent.
    #[must_use]
    pub fn snapshot_row(&self, id: u32, kind: SnapshotKind) -> Row {
        Row::RepositorySnapshot {
            id,
            kind,
            config_digest: hex::encode(self.config.digest),
            hooks: self.listing.hooks.clone(),
            info_attributes: self.listing.info_attributes.clone(),
            info_exclude: self.listing.info_exclude.clone(),
            absent_names: self.listing.absent_names.clone(),
        }
    }

    /// Opens `config` afresh by the tree's path and requires the held file: its identity, one name,
    /// its size and the SHA-256 of its bytes.
    fn config_is_unchanged(&self) -> bool {
        let path = format!(r"{}\.git\config", self.path);
        let wide = wide_path(Path::new(&path));
        // SAFETY: the path is NUL-terminated and the call keeps nothing of it.
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        // text: hold_config_is_unchanged-1
        let Ok(handle) = Handle::new(raw, "reading the repository's config") else {
            return false;
        };
        let Ok(identity) = key_of(&handle) else {
            return false;
        };
        let Ok(standard) = query::<FILE_STANDARD_INFO>(
            &handle,
            FileStandardInfo,
            "reading the configuration's size and names",
        ) else {
            return false;
        };
        // A reparse point set through a handle that may only write attributes changes no byte, size
        // or name, so the attributes are read again.
        let Ok(tag) = query::<FILE_ATTRIBUTE_TAG_INFO>(
            &handle,
            FileAttributeTagInfo,
            "reading the configuration's attributes",
        ) else {
            return false;
        };
        if tag.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0 {
            return false;
        }
        if identity != self.config.identity
            || standard.NumberOfLinks != self.config.link_count
            || standard.DeletePending
            || standard.EndOfFile.cast_unsigned() != self.config.bytes.len() as u64
        {
            return false;
        }
        match read_all(&handle) {
            Ok(Some(bytes)) => Sha256::digest(&bytes).as_slice() == self.config.digest,
            // A read that failed or found more bytes shows nothing, so the file is not the same.
            Ok(None) | Err(_) => false,
        }
    }
}

/// Whether the held folder is still the object it was, at the path it was opened at, and still no
/// reparse point. A read that fails shows nothing, so the folder is then not shown to be the same.
fn folder_is_unchanged(folder: &DirHandle) -> bool {
    let tag = query::<FILE_ATTRIBUTE_TAG_INFO>(
        folder.handle(),
        FileAttributeTagInfo,
        "reading a folder's attributes",
    );
    match (key_of(folder.handle()), final_path(folder.handle()), tag) {
        (Ok(key), Ok(path), Ok(tag)) => {
            key == folder.key()
                && path == folder.path()
                && tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
        }
        _ => false,
    }
}

fn refuse(kind: RefusedKind, rule: &'static str, words: &str) -> Refusal {
    Refusal::new(kind, rule, words)
}

fn failed(failure: &ffi::Error) -> Refusal {
    Refusal::new(
        RefusedKind::Admission,
        RULE_HOLD_FAILED,
        &format!("{HOLD_FAILED_WORDS}: {failure}"),
    )
}

/// The words, a colon and the text, with the text cut at its start when the whole would be longer
/// than a detail may be: the last parts of a path are what a person recognises, as in the
/// admission's replies.
fn named(words: &str, path: &str) -> String {
    let room = MAX_DETAIL_BYTES.saturating_sub(words.len() + ": ".len());
    format!("{words}: {}", cut_start(path, room))
}

/// Holds the project the request names: takes the text apart, opens the drive's root and then each
/// directory down to the tree, and opens its `.git` and its `config`. The text is never opened as a
/// whole: nothing is opened before its form is known to be a path on a local drive, and no link
/// on the way is followed.
///
/// # Errors
///
/// Refuses when the text is not a path on a local drive, when a folder on the way is missing, a
/// link or a mounted volume, when the drive is not a local disk volume the broker runs on, when the
/// person cannot read the project, when the project has no `.git` folder or no `config`, when the
/// `config` has more than one name or is open for writing elsewhere, or when it is over the bound.
pub fn hold_tree(path: &str, client: &ClientIdentity) -> Result<TreeHold, Refusal> {
    let chain = open_chain(path)?;
    let tree = chain.last().ok_or_else(|| {
        refuse(
            RefusedKind::Admission,
            RULE_FOLDER_CHANGED,
            FOLDER_CHANGED_WORDS,
        )
    })?;
    // The hold keeps the path with its long-path prefix, which later opens by name use; the
    // refusals show it as the person spells it.
    let dos = dos_path(tree.handle())?;
    let display = spelled(&dos).to_owned();
    person_reads(client, tree.handle(), &display)?;
    let git_name: Vec<u16> = ".git".encode_utf16().collect();
    let git_dir = match tree.open_directory_named(&git_name, LIST) {
        Ok(Ok(opened)) => opened,
        Ok(Err(Lost::Gone | Lost::IdentityChanged | Lost::MovedOut)) => {
            return Err(refuse(RefusedKind::Repository, RULE_NO_GIT, NO_GIT_WORDS));
        }
        Ok(Err(Lost::Refused(code))) => {
            // text: hold_folder-1
            return Err(failed(&ffi::error(code, "opening the .git folder")));
        }
        Err(failure) => return Err(failed(&failure)),
    };
    person_reads(client, git_dir.handle(), &format!("{display}\\.git"))?;
    let config = read_config(&git_dir, client, &display)?;
    if listing::modules_present(&git_dir) {
        return Err(refuse(RefusedKind::Repository, RULE_MODULES, MODULES_WORDS));
    }
    if let Some(name) = listing::present_names(&git_dir).first() {
        return Err(refuse(
            RefusedKind::Repository,
            RULE_ABSENT_NAME,
            &named(ABSENT_NAME_WORDS, name),
        ));
    }
    let (listing, listed_files) = take_listing(&git_dir)?;
    let states = listing::present_states(&git_dir);
    let identity = TreeIdentity {
        chain: chain.iter().map(DirHandle::key).collect(),
    };
    Ok(TreeHold {
        chain,
        git_dir,
        config,
        identity,
        listing,
        states,
        listed_files,
        path: dos,
    })
}

/// Takes the listing of the held `.git` folder and holds each listed file, or refuses the
/// repository.
fn take_listing(git_dir: &DirHandle) -> Result<(RepositoryListing, Vec<Handle>), Refusal> {
    listing::take_held(git_dir).map_err(|failure| match failure {
        Failure::TooLarge => refuse(
            RefusedKind::Repository,
            RULE_LISTING_BOUND,
            LISTING_BOUND_WORDS,
        ),
        Failure::Moved => refuse(
            RefusedKind::Admission,
            RULE_FOLDER_CHANGED,
            FOLDER_CHANGED_WORDS,
        ),
        Failure::Os(failure) => failed(&failure),
    })
}

fn person_reads(client: &ClientIdentity, handle: &Handle, path: &str) -> Result<(), Refusal> {
    let descriptor = Sd::of_handle(handle).map_err(|failure| failed(&failure))?;
    if client.may(&descriptor, Right::ReadData) {
        Ok(())
    } else {
        Err(Refusal::new(
            RefusedKind::Admission,
            RULE_PERSON,
            &named(PERSON_WORDS, path),
        ))
    }
}

fn refusal_for_anchor(refusal: &AnchorRefusal, path: &str) -> Refusal {
    match refusal {
        AnchorRefusal::ReparsePoint => refuse(
            RefusedKind::Admission,
            RULE_FOLDER_LINK,
            &named(FOLDER_LINK_WORDS, path),
        ),
        AnchorRefusal::NotADirectory => refuse(
            RefusedKind::Admission,
            RULE_FOLDER_MISSING,
            FOLDER_MISSING_WORDS,
        ),
        AnchorRefusal::Volume(volume) => refuse(
            RefusedKind::Admission,
            RULE_FOLDER_CHANGED,
            &volume.to_string(),
        ),
    }
}

fn not_folder_refusal(refused: &NotFolder, path: &str) -> Refusal {
    match refused {
        NotFolder::Gone => refuse(
            RefusedKind::Admission,
            RULE_FOLDER_MISSING,
            FOLDER_MISSING_WORDS,
        ),
        NotFolder::Link {
            volume_mount: true, ..
        } => refuse(RefusedKind::Admission, RULE_FOLDER_MOUNT, MOUNT_POINT_WORDS),
        // A folder that a cloud service synchronises is not a link the person can follow: it gets
        // the words that say why the broker does not accept it.
        NotFolder::Link { tag, .. } if is_cloud_tag(*tag) => reparse_refusal(*tag, path),
        NotFolder::Link { .. } => refuse(
            RefusedKind::Admission,
            RULE_FOLDER_LINK,
            &named(FOLDER_LINK_WORDS, path),
        ),
        NotFolder::MovedOut => refuse(
            RefusedKind::Admission,
            RULE_FOLDER_CHANGED,
            FOLDER_CHANGED_WORDS,
        ),
        NotFolder::Refused(code) => {
            // text: hold_folder-2
            failed(&ffi::error(*code, "opening a directory of the project"))
        }
    }
}
/// Opens the folders the text names, one beneath the other, from the root of its drive. The form
/// and the drive are checked before anything is opened, and the walk goes by names beneath held
/// folders, so no link on the way is followed.
fn open_chain(path: &str) -> Result<Vec<DirHandle>, Refusal> {
    let Some(local) = local_path::parse(path) else {
        return Err(refuse(
            RefusedKind::Admission,
            RULE_FOLDER_FORM,
            FOLDER_FORM_WORDS,
        ));
    };
    check_drive(local.drive)?;
    let root_text = format!("{}:\\", local.drive);
    let root = match DirHandle::open_anchor_with(Path::new(&root_text), LIST) {
        Ok(Ok(root)) => root,
        Ok(Err(refusal)) => return Err(refusal_for_anchor(&refusal, path)),
        Err(failure) if failure.code == 2 || failure.code == 3 => {
            return Err(refuse(
                RefusedKind::Admission,
                RULE_FOLDER_MISSING,
                FOLDER_MISSING_WORDS,
            ));
        }
        Err(failure) => return Err(failed(&failure)),
    };
    let mut chain = vec![root];
    for name in &local.names {
        let parent = chain.last().ok_or_else(|| {
            refuse(
                RefusedKind::Admission,
                RULE_FOLDER_CHANGED,
                FOLDER_CHANGED_WORDS,
            )
        })?;
        let next = match parent.open_folder_spelled(name, LIST) {
            Ok(Ok(next)) => next,
            Ok(Err(refused)) => return Err(not_folder_refusal(&refused, path)),
            Err(failure) => return Err(failed(&failure)),
        };
        chain.push(next);
    }
    Ok(chain)
}

/// Reads where a drive letter leads, without opening what it leads to, and refuses a letter that
/// is not a local disk volume. The call reads the link `\??\X:` of the caller's own device names
/// and answers its target text; it opens no device, so a letter that stands for a share, for a
/// folder or for any other device reaches nothing.
fn check_drive(letter: char) -> Result<(), Refusal> {
    let name: Vec<u16> = format!("{letter}:").encode_utf16().chain([0]).collect();
    let mut buffer = vec![0_u16; 1024];
    loop {
        // SAFETY: the name is NUL-terminated, the buffer length is passed, and the call keeps
        // neither.
        let count =
            unsafe { QueryDosDeviceW(name.as_ptr(), buffer.as_mut_ptr(), buffer.len() as u32) };
        if count != 0 {
            buffer.truncate(count as usize);
            break;
        }
        // text: hold_drive-1
        let failure = ffi::last("reading where the drive letter leads");
        if failure.code == 2 {
            return Err(refuse(
                RefusedKind::Admission,
                RULE_FOLDER_MISSING,
                FOLDER_MISSING_WORDS,
            ));
        }
        if failure.code == 122 && buffer.len() < MAX_TARGET_UNITS {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        return Err(failed(&failure));
    }
    // The first text of the answer is the link in force; a letter may carry others beneath it.
    let target = buffer.split(|unit| *unit == 0).next().unwrap_or(&[]);
    if local_path::is_local_volume_target(target) {
        Ok(())
    } else {
        Err(refuse(
            RefusedKind::Admission,
            RULE_FOLDER_FORM,
            FOLDER_FORM_WORDS,
        ))
    }
}

/// The path of an open folder in its DOS form (`\\?\C:\a\b`).
fn dos_path(handle: &Handle) -> Result<String, Refusal> {
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
            // text: hold_resolve-2
            return Err(failed(&ffi::last(
                "reading the project folder's final path",
            )));
        }
        if (length as usize) < buffer.len() {
            buffer.truncate(length as usize);
            return Ok(String::from_utf16_lossy(&buffer));
        }
        buffer.resize(length as usize + 1, 0);
    }
}

/// Opens `config` shared for reading only, requires an ordinary file with one name inside the
/// bound, and reads its bytes from the handle.
fn read_config(
    git_dir: &DirHandle,
    client: &ClientIdentity,
    display: &str,
) -> Result<ConfigSnapshot, Refusal> {
    let name: Vec<u16> = "config".encode_utf16().collect();
    // The attributes come first, from a handle that asks for no data: an encrypted file refuses a
    // data open to an account that has no key, and the refusal then says why, not "access denied".
    let path = format!("{display}\\.git\\config");
    {
        let looked = DirHandle::open_beneath_shared(
            git_dir.handle(),
            &name,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
        );
        if let Ok(looked) = looked {
            let tag: FILE_ATTRIBUTE_TAG_INFO = query(
                &looked,
                FileAttributeTagInfo,
                "reading the configuration's attributes",
            )
            .map_err(|failure| failed(&failure))?;
            if let Some(refusal) = attributes_refusal(tag.FileAttributes, &path) {
                return Err(refusal);
            }
        }
    }
    let handle = match DirHandle::open_beneath_shared(
        git_dir.handle(),
        &name,
        FILE_GENERIC_READ,
        FILE_SHARE_READ,
        FILE_OPEN,
    ) {
        Ok(handle) => handle,
        Err(failure) if failure.code == 2 || failure.code == 3 => {
            return Err(refuse(
                RefusedKind::Repository,
                RULE_NO_CONFIG,
                NO_CONFIG_WORDS,
            ));
        }
        Err(failure) if failure.code == 32 => {
            return Err(refuse(
                RefusedKind::Repository,
                RULE_CONFIG_BUSY,
                CONFIG_BUSY_WORDS,
            ));
        }
        Err(failure) => return Err(failed(&failure)),
    };
    let tag: FILE_ATTRIBUTE_TAG_INFO = query(
        &handle,
        FileAttributeTagInfo,
        "reading the configuration's attributes",
    )
    .map_err(|failure| failed(&failure))?;
    let standard: FILE_STANDARD_INFO = query(
        &handle,
        FileStandardInfo,
        "reading the configuration's size and names",
    )
    .map_err(|failure| failed(&failure))?;
    if tag.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0
        || standard.NumberOfLinks != 1
        || standard.DeletePending
    {
        return Err(refuse(
            RefusedKind::Repository,
            RULE_CONFIG_LINKS,
            CONFIG_LINKS_WORDS,
        ));
    }
    person_reads(client, &handle, &path)?;
    let size = standard.EndOfFile.cast_unsigned();
    if size > MAX_CONFIG_BYTES {
        return Err(refuse(
            RefusedKind::Configuration,
            RULE_CONFIG_SIZE,
            CONFIG_SIZE_WORDS,
        ));
    }
    let bytes = read_all(&handle).map_err(|failure| failed(&failure))?;
    let Some(bytes) = bytes else {
        return Err(refuse(
            RefusedKind::Configuration,
            RULE_CONFIG_SIZE,
            CONFIG_SIZE_WORDS,
        ));
    };
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    let identity = key_of(&handle).map_err(|failure| failed(&failure))?;
    Ok(ConfigSnapshot {
        handle,
        digest,
        bytes,
        identity,
        link_count: standard.NumberOfLinks,
    })
}

/// Reads the file from its start to its end through a second handle of the same open, so the
/// sharing that the hold took is the one the read is made under. `None` when it holds more than the
/// bound.
fn read_all(handle: &Handle) -> ffi::Result<Option<Vec<u8>>> {
    // SAFETY: the handle is open for the whole call.
    let borrowed = unsafe { BorrowedHandle::borrow_raw(handle.raw()) };
    let mut file = File::from(
        borrowed
            .try_clone_to_owned()
            .map_err(|failure| read_failed(&failure))?,
    );
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|failure| read_failed(&failure))?;
    Ok((bytes.len() as u64 <= MAX_CONFIG_BYTES).then_some(bytes))
}

fn read_failed(failure: &std::io::Error) -> ffi::Error {
    let code = failure.raw_os_error().map_or(0, i32::cast_unsigned);
    // text: hold_read_all-1
    ffi::error(code, "reading the repository's config")
}
