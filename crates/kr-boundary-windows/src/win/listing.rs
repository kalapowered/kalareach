//! What a repository's Git directory holds that the broker cannot hold open: the names that must be
//! absent, the hooks folder and the `info\attributes` file, each file with its digest.
//!
//! The holds of [`super::hold`] stop a rename, a replacement and a deletion of the held objects, and
//! they do not stop the creation of a new name or a write to a file that is not held. A taken-over
//! Git can leave a `commondir` file for the next operation, or a hook that the person's own Git
//! runs later. The broker takes one listing when it holds the tree and compares it with a fresh one
//! before the resume and at the end, by name, identity, size and digest. At the hold it also keeps
//! each listed file open for reading and sharing it for reading only, so that no account can write
//! to, rename or delete a hook or the attributes file while the tree is held, whatever view of it
//! a process keeps: a kept view maps the file's data, and that mapping outlives the broker's check.

#![allow(unsafe_code)]

use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read as _;
use std::os::windows::io::BorrowedHandle;

use sha2::{Digest, Sha256};
use windows_sys::Wdk::Storage::FileSystem::FILE_OPEN;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
    FILE_GENERIC_READ, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FileAttributeTagInfo,
};

use crate::filekey::FileKey;
use crate::journal::limits::{HOOKS, NAME_BYTES, json_bytes};
use crate::journal::rows::DigestedFile;
use crate::operation::state::STATE_NAMES;
use crate::repository::attributes::MAX_ATTRIBUTES_BYTES;

use super::ffi::{self, Handle};
use super::walk::{
    Bounds, Child, DirHandle, Entry, Kind, LIST, Lost, Verdict, WalkError, query, walk,
};

/// The names that must be absent from a held Git directory, relative to it. A taken-over Git can
/// make each after the hold, and none is held.
pub const ABSENT_NAMES: [&str; 6] = [
    "commondir",
    "worktrees",
    "config.worktree",
    r"objects\info\alternates",
    r"objects\info\http-alternates",
    r"info\grafts",
];

/// The most objects the walk of the hooks folder visits.
pub const MAX_OBJECTS: usize = 256;

/// The deepest level of the hooks folder that is listed, its own children being the first.
pub const MAX_DEPTH: usize = 4;

/// The most bytes a hook may hold.
pub const MAX_FILE_BYTES: u64 = 1_048_576;

/// What the broker took of a Git directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepositoryListing {
    /// Every object of the hooks folder, by name relative to the Git directory: a file with its
    /// digest, a folder as `name\`, a reparse point as `name:link`.
    pub hooks: Vec<DigestedFile>,
    /// The `info\attributes` file, when there is one.
    pub info_attributes: Option<DigestedFile>,
    /// The `info\exclude` file, when there is one.
    pub info_exclude: Option<DigestedFile>,
    /// The names that must be absent.
    pub absent_names: Vec<String>,
}

/// Why a listing could not be taken.
#[derive(Debug)]
pub(super) enum Failure {
    /// The folder or a file is over a bound of the listing.
    TooLarge,
    /// An object was not where the listing named it, or is not the kind it was.
    Moved,
    /// The platform refused a call.
    Os(ffi::Error),
}

impl From<ffi::Error> for Failure {
    fn from(failure: ffi::Error) -> Self {
        Failure::Os(failure)
    }
}

fn failure_of(lost: &Lost) -> Failure {
    match lost {
        // text: listing_lost-1
        Lost::Refused(code) => Failure::Os(ffi::error(
            *code,
            "reading a hook or the attributes file of the repository",
        )),
        Lost::Gone | Lost::IdentityChanged | Lost::MovedOut => Failure::Moved,
    }
}

fn is_link(child: &Child) -> bool {
    child.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

fn is_folder(child: &Child) -> bool {
    !is_link(child) && child.attributes & FILE_ATTRIBUTE_DIRECTORY != 0
}

/// A folder or a link, which the listing records by identity alone: no size and the digest of
/// nothing.
fn plain(name: String, key: FileKey) -> DigestedFile {
    DigestedFile {
        name,
        key,
        size: 0,
        sha256: hex::encode(Sha256::digest([])),
    }
}

/// The size of the file and the SHA-256 of its bytes, read from the start through a second handle
/// of the same open; `None` when the file holds more than `limit` bytes.
fn digest(handle: &Handle, limit: u64) -> ffi::Result<Option<(u64, [u8; 32])>> {
    // SAFETY: the handle is open for the whole call.
    let borrowed = unsafe { BorrowedHandle::borrow_raw(handle.raw()) };
    let mut file = File::from(
        borrowed
            .try_clone_to_owned()
            .map_err(|failure| read_failed(&failure))?,
    );
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = vec![0_u8; 16 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|failure| read_failed(&failure))?;
        if count == 0 {
            break;
        }
        total += count as u64;
        if total > limit {
            return Ok(None);
        }
        hasher.update(&buffer[..count]);
    }
    Ok(Some((total, hasher.finalize().into())))
}

fn read_failed(failure: &std::io::Error) -> ffi::Error {
    let code = failure.raw_os_error().map_or(0, i32::cast_unsigned);
    // text: listing_digest-1
    ffi::error(
        code,
        "reading a hook or the attributes file of the repository",
    )
}

/// Records one object that `dir` lists: a file by its digest, a folder or a link by its identity.
/// `name` is relative to the Git directory.
fn record(
    dir: &DirHandle,
    child: &Child,
    name: String,
    limit: u64,
    holds: Option<&mut Vec<Handle>>,
) -> Result<DigestedFile, Failure> {
    // The name is counted as the journal records it: a folder's ends in a backslash and a link's in
    // `:link`, and each backslash is two bytes of the row's text.
    let spelled = if is_link(child) {
        format!("{name}:link")
    } else if is_folder(child) {
        format!("{name}\\")
    } else {
        name.clone()
    };
    if json_bytes(&spelled) > NAME_BYTES {
        return Err(Failure::TooLarge);
    }
    if is_link(child) || is_folder(child) {
        return Ok(plain(spelled, child.key));
    }
    // A file that is kept is shared for reading only; a fresh look shares for writing too, which the
    // kept handles allow, since they ask for no write.
    let share = if holds.is_some() {
        FILE_SHARE_READ
    } else {
        FILE_SHARE_READ | FILE_SHARE_WRITE
    };
    let opened = match dir.open_child_shared(child, FILE_GENERIC_READ, share)? {
        Ok(opened) if opened.kind == Kind::File => opened,
        Ok(_) => return Err(Failure::Moved),
        Err(lost) => return Err(failure_of(&lost)),
    };
    let Some((size, sha)) = digest(&opened.handle, limit)? else {
        return Err(Failure::TooLarge);
    };
    let file = DigestedFile {
        name,
        key: opened.key,
        size,
        sha256: hex::encode(sha),
    };
    if let Some(kept) = holds {
        kept.push(opened.handle);
    }
    Ok(file)
}

/// Opens a listed folder for listing.
fn open_folder(parent: &DirHandle, child: &Child) -> Result<DirHandle, Failure> {
    match parent.open_child(child, LIST)? {
        Ok(opened) if opened.kind == Kind::Directory => Ok(DirHandle::from_opened(opened)?),
        Ok(_) => Err(Failure::Moved),
        Err(lost) => Err(failure_of(&lost)),
    }
}

/// The name of `child`, listed by `dir`, relative to the Git directory `git`.
fn relative_name(git: &DirHandle, dir: &DirHandle, child: &Child) -> String {
    let below = dir.path().get(git.path().len() + 1..).unwrap_or_default();
    let parent = String::from_utf16_lossy(below);
    if parent.is_empty() {
        child.display()
    } else {
        format!("{parent}\\{}", child.display())
    }
}

/// Lists the hooks folder, every object by the walk of [`MAX_OBJECTS`] and [`MAX_DEPTH`].
fn list_hooks(
    git: &DirHandle,
    child: &Child,
    hooks: &mut Vec<DigestedFile>,
    mut holds: Option<&mut Vec<Handle>>,
) -> Result<(), Failure> {
    if !is_folder(child) {
        // A file or a link where the folder belongs is recorded as it is, and nothing is entered.
        hooks.push(record(git, child, child.display(), MAX_FILE_BYTES, holds)?);
        return Ok(());
    }
    let folder = open_folder(git, child)?;
    let mut found: Option<Failure> = None;
    let mut visit = |entry: &Entry<'_>| -> ffi::Result<Verdict> {
        let name = relative_name(git, entry.dir, entry.child);
        match record(
            entry.dir,
            entry.child,
            name,
            MAX_FILE_BYTES,
            holds.as_deref_mut(),
        ) {
            Ok(file) => hooks.push(file),
            Err(failure) => {
                found.get_or_insert(failure);
            }
        }
        Ok(if is_folder(entry.child) {
            Verdict::Descend
        } else {
            Verdict::Skip
        })
    };
    let report = walk(
        &folder,
        Bounds {
            objects: MAX_OBJECTS,
            depth: MAX_DEPTH,
        },
        &mut visit,
    )
    .map_err(|failure| match failure {
        WalkError::Os(failure) => Failure::Os(failure),
        WalkError::TooLarge(_) | WalkError::TooDeep(_) => Failure::TooLarge,
    })?;
    if let Some(failure) = found {
        return Err(failure);
    }
    match report.problems.first() {
        Some(problem) => Err(failure_of(&problem.lost)),
        None => Ok(()),
    }
}

/// The `info\attributes` and `info\exclude` files, when the `info` folder has them: in that order.
fn read_info(
    git: &DirHandle,
    child: &Child,
    mut holds: Option<&mut Vec<Handle>>,
) -> Result<(Option<DigestedFile>, Option<DigestedFile>), Failure> {
    let name = child.display();
    if !is_folder(child) {
        // A file or a link where the folder belongs is recorded as it is, and nothing is entered.
        return Ok((Some(record(git, child, name, MAX_FILE_BYTES, holds)?), None));
    }
    let info = open_folder(git, child)?;
    let Some(inside) = info.children_up_to(MAX_OBJECTS)? else {
        return Err(Failure::TooLarge);
    };
    let (mut attributes, mut exclude) = (None, None);
    for inner in inside {
        let relative = format!("{name}\\{}", inner.display());
        if inner.display().eq_ignore_ascii_case("attributes") {
            let limit = MAX_ATTRIBUTES_BYTES as u64;
            attributes = Some(record(
                &info,
                &inner,
                relative,
                limit,
                holds.as_deref_mut(),
            )?);
        } else if inner.display().eq_ignore_ascii_case("exclude") {
            exclude = Some(record(
                &info,
                &inner,
                relative,
                MAX_FILE_BYTES,
                holds.as_deref_mut(),
            )?);
        }
    }
    Ok((attributes, exclude))
}

/// Takes the listing of the held Git directory.
///
/// # Errors
///
/// Fails when the hooks folder or a file is over a bound, when an object is not where the listing
/// named it, or when the platform refuses a call.
pub(super) fn take(git: &DirHandle) -> Result<RepositoryListing, Failure> {
    take_by(git, None)
}

/// Takes the listing of the held Git directory and keeps each listed file open for reading, shared
/// for reading only: the handles are returned for the hold to keep until the tree is let go.
///
/// # Errors
///
/// Fails as [`take`] does, and when a listed file is open for writing elsewhere.
pub(super) fn take_held(git: &DirHandle) -> Result<(RepositoryListing, Vec<Handle>), Failure> {
    let mut kept = Vec::new();
    let listing = take_by(git, Some(&mut kept))?;
    Ok((listing, kept))
}

fn take_by(
    git: &DirHandle,
    mut holds: Option<&mut Vec<Handle>>,
) -> Result<RepositoryListing, Failure> {
    let mut hooks = Vec::new();
    let mut info_attributes = None;
    let mut info_exclude = None;
    let Some(inside) = git.children_up_to(MAX_OBJECTS)? else {
        return Err(Failure::TooLarge);
    };
    for child in inside {
        let name = child.display();
        if name.eq_ignore_ascii_case("hooks") {
            list_hooks(git, &child, &mut hooks, holds.as_deref_mut())?;
        } else if name.eq_ignore_ascii_case("info") {
            (info_attributes, info_exclude) = read_info(git, &child, holds.as_deref_mut())?;
        }
    }
    if hooks.len() > HOOKS {
        return Err(Failure::TooLarge);
    }
    hooks.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(RepositoryListing {
        hooks,
        info_attributes,
        info_exclude,
        absent_names: ABSENT_NAMES.iter().map(|name| (*name).to_owned()).collect(),
    })
}

/// The names of [`ABSENT_NAMES`] that are present in the held Git directory now. A name that cannot
/// be shown absent counts as present: only a platform answer of "not found" shows it, and a folder
/// on the way that is a link or not a folder hides what is beyond it.
pub(super) fn present_names(git: &DirHandle) -> Vec<String> {
    ABSENT_NAMES
        .iter()
        .filter(|name| is_present(git, name))
        .map(|name| (*name).to_owned())
        .collect()
}

/// Whether the held Git directory has a `modules` folder: the Git directories of submodules, with
/// settings and hooks of their own that the broker does not hold. The hold refuses a repository
/// that has one, so one that is there at the end is new. A name that cannot be shown absent counts
/// as present.
pub(super) fn modules_present(git: &DirHandle) -> bool {
    is_present(git, "modules")
}

/// The folders of the Git directory that the person's own Git writes into, by name.
pub const WRITTEN_FOLDERS: [&str; 4] = ["objects", "refs", "logs", "info"];

/// The names of [`WRITTEN_FOLDERS`] that are a reparse point now. A junction or a link in the place
/// of one sends what the person's next Git writes, as the person, to a folder where the boundary
/// account has no right. A folder that is not there is no link; one that cannot be read is named.
pub(super) fn linked_folders(git: &DirHandle) -> Vec<String> {
    WRITTEN_FOLDERS
        .iter()
        .filter(|name| is_a_link(git, name))
        .map(|name| (*name).to_owned())
        .collect()
}

fn is_a_link(git: &DirHandle, name: &str) -> bool {
    let units: Vec<u16> = name.encode_utf16().collect();
    match DirHandle::open_beneath(git.handle(), &units, FILE_READ_ATTRIBUTES, true, FILE_OPEN) {
        Ok(handle) => match query::<FILE_ATTRIBUTE_TAG_INFO>(
            &handle,
            FileAttributeTagInfo,
            "reading the attributes of a folder of the Git directory",
        ) {
            Ok(tag) => tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0,
            Err(_) => true,
        },
        Err(failure) if failure.code == 2 || failure.code == 3 => false,
        Err(_) => true,
    }
}

/// The names of [`STATE_NAMES`] that are present in the held Git directory now: the states of an
/// operation in progress. The admitted commands make none of them, so one that was not there at the
/// hold is new, and the next `--continue` of the person's own Git would run what it holds.
pub(super) fn present_states(git: &DirHandle) -> Vec<String> {
    STATE_NAMES
        .iter()
        .filter(|name| is_present(git, name))
        .map(|name| (*name).to_owned())
        .collect()
}

fn is_present(git: &DirHandle, name: &str) -> bool {
    let parts: Vec<Vec<u16>> = name
        .split('\\')
        .map(|part| part.encode_utf16().collect())
        .collect();
    let mut held: Option<Handle> = None;
    for (index, part) in parts.iter().enumerate() {
        let last = index + 1 == parts.len();
        let root = held.as_ref().map_or_else(|| git.handle(), |handle| handle);
        let access = if last { 0 } else { FILE_LIST_DIRECTORY };
        match DirHandle::open_beneath(root, part, access, true, FILE_OPEN) {
            Err(failure) if failure.code == 2 || failure.code == 3 => return false,
            Err(_) => return true,
            Ok(handle) => {
                if last {
                    return true;
                }
                let plain_folder = match query::<FILE_ATTRIBUTE_TAG_INFO>(
                    &handle,
                    FileAttributeTagInfo,
                    "reading the attributes of a name on the way to one that must be absent",
                ) {
                    Ok(tag) => {
                        tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0
                            && tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
                    }
                    // A read that fails shows nothing, so the name on the way is not shown to be a folder.
                    Err(_) => false,
                };
                if !plain_folder {
                    return true;
                }
                held = Some(handle);
            }
        }
    }
    false
}

fn same(held: &DigestedFile, now: &DigestedFile) -> bool {
    held.key == now.key && held.size == now.size && held.sha256 == now.sha256
}

fn compare(held: &[DigestedFile], now: &[DigestedFile], names: &mut BTreeSet<String>) {
    for before in held {
        match now.iter().find(|after| after.name == before.name) {
            Some(after) if same(before, after) => {}
            _ => {
                names.insert(before.name.clone());
            }
        }
    }
    for after in now {
        if !held.iter().any(|before| before.name == after.name) {
            names.insert(after.name.clone());
        }
    }
}

/// The names that the two listings do not hold alike, sorted: an object that is new, gone, or
/// another identity, size or content.
pub(super) fn differences(held: &RepositoryListing, now: &RepositoryListing) -> Vec<String> {
    let mut names = BTreeSet::new();
    compare(&held.hooks, &now.hooks, &mut names);
    let before: Vec<DigestedFile> = held.info_attributes.iter().cloned().collect();
    let after: Vec<DigestedFile> = now.info_attributes.iter().cloned().collect();
    compare(&before, &after, &mut names);
    let before: Vec<DigestedFile> = held.info_exclude.iter().cloned().collect();
    let after: Vec<DigestedFile> = now.info_exclude.iter().cloned().collect();
    compare(&before, &after, &mut names);
    names.into_iter().collect()
}
