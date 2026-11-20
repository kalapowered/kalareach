//! The folder an installation for a declared agent is written under, walked from one handle on it.
//! It lives beside the native bridge's walk, whose handle type it uses.
//!
//! A package declares the places, so the host cannot know them to be its own. Every name an
//! installation for a declared word reads, writes or removes is reached from the handle this host
//! opened once on the selected root (the home folder, or the project folder the request names),
//! one component at a time, each opened without following a link. A link or a file at any
//! component stops the walk by name before anything below it is touched, so a place a person
//! replaced with a link between the check and the write is refused rather than followed. A file is
//! staged under a temporary name in its destination folder, through the handle this walk holds on
//! that folder, and published from there; the folder is flushed after. A folder that another user
//! can change, and a file that another user can change, are refused, and every decision about who
//! can change one is read through the handle that holds it.

use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};

use kr_protocol::scalars::Digest256;

use super::tree::{
    Cause, Child, Control, Dir, Entry, Fetched, Identity, Listing, Protection, temporary_name,
};
use crate::catalogue::files::{digest_of, storage};
use crate::error::{ControllerError, Result};

/// The most bytes of one file this walk reads: a configuration document an agent keeps, which the
/// host rewrites whole.
const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;

/// A refusal the person is told of: the place is not one an installation may use.
fn refused(detail: String) -> ControllerError {
    ControllerError::PermissionDenied { detail }
}

/// What the last name of a place is to be: a file the installation writes, or a folder it writes
/// into.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Expect {
    /// A regular file.
    File,
    /// A folder.
    Folder,
}

/// One selected root, held open.
#[derive(Debug)]
pub(crate) struct Anchor {
    root: Dir,
    path: PathBuf,
    /// Where the root is, with every link on the way to it resolved, as it was when it was opened.
    actual: PathBuf,
}

/// A place below the root, split into the folders on the way and the last name.
struct Place<'a> {
    folders: Vec<&'a str>,
    name: &'a str,
}

impl Anchor {
    /// Opens the selected root once, or says there is none where it is not there. The root itself is
    /// opened by its name: it is the one the request selected, and a link there is the person's
    /// own layout.
    pub(crate) fn open(root: &Path) -> Result<Option<Self>> {
        match Dir::open(root) {
            Ok(handle) => {
                let actual = std::fs::canonicalize(root).map_err(storage)?;
                // The location found is the folder that was opened, or the root moved in between
                // and nothing below it is trusted.
                let there = Dir::open(&actual).map_err(storage)?;
                if there.identity() != handle.identity() {
                    return Err(refused(format!(
                        "{} changed while it was opened, so this host does not use anything below it",
                        root.display()
                    )));
                }
                Ok(Some(Self {
                    root: handle,
                    path: root.to_path_buf(),
                    actual,
                }))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(storage(error)),
        }
    }

    /// Where `path`, a place below the selected root, is as the file system reaches it: the root's
    /// actual location with the place's own components after it, or none for a path outside the
    /// root.
    pub(crate) fn reached_by(&self, path: &Path) -> Option<PathBuf> {
        path.strip_prefix(&self.path)
            .ok()
            .map(|below| self.actual.join(below))
    }

    /// True when `path` is the selected root itself.
    fn is_root(&self, path: &Path) -> bool {
        path == self.path
    }

    /// Splits `path` into the components below the root, or refuses a path that lies outside it,
    /// that holds `.` or `..`, or that names the root itself.
    fn place<'a>(&self, path: &'a Path) -> Result<Place<'a>> {
        let outside = || {
            ControllerError::InvalidArgument(format!(
                "{} lies outside {}, which is the folder this installation is written under",
                path.display(),
                self.path.display()
            ))
        };
        let below = path.strip_prefix(&self.path).map_err(|_| outside())?;
        let mut names = Vec::new();
        for component in below.components() {
            match component {
                Component::Normal(name) => names.push(name.to_str().ok_or_else(outside)?),
                _ => return Err(outside()),
            }
        }
        let name = names.pop().ok_or_else(outside)?;
        Ok(Place {
            folders: names,
            name,
        })
    }

    /// Opens the folder `place` is in, from the root, without following a link. Where a folder is
    /// missing, `make` says whether to make it; `None` is a missing folder that was not made.
    fn parent(&self, place: &Place<'_>, make: bool) -> Result<Option<Dir>> {
        let mut held: Option<Dir> = None;
        for (index, component) in place.folders.iter().enumerate() {
            let from = held.as_ref().unwrap_or(&self.root);
            let mut child = from.child(component).map_err(storage)?;
            if matches!(child, Child::Absent) && make {
                from.make_child(component).map_err(storage)?;
                from.flush().map_err(storage)?;
                child = from.child(component).map_err(storage)?;
            }
            match child {
                Child::Directory(next) => held = Some(next),
                Child::Absent => return Ok(None),
                Child::NotADirectory => {
                    return Err(refused(format!(
                        "{} is a link or a file, and an installation follows no link and writes \
                         nothing below a file",
                        self.path
                            .join(place.folders[..=index].iter().collect::<PathBuf>())
                            .display()
                    )));
                }
            }
        }
        match held {
            Some(directory) => Ok(Some(directory)),
            // The root itself: the handle this walk holds, never its name again.
            None => Ok(Some(self.root.duplicate().map_err(storage)?)),
        }
    }

    /// Refuses a link or a file at any folder on the way to `path`, a link at its last name, and a
    /// last name that is a folder where a file is to be written or a file where a folder is to be
    /// made, before anything is written. A folder or a name that is not there is not an error.
    pub(crate) fn refuse_links(&self, path: &Path, expect: Expect) -> Result<()> {
        if self.is_root(path) {
            return Ok(());
        }
        let place = self.place(path)?;
        let Some(parent) = self.parent(&place, false)? else {
            return Ok(());
        };
        match (parent.entry(place.name).map_err(storage)?, expect) {
            (Entry::Other, _) => Err(refused(format!(
                "{} is a link or a special file, and an installation follows no link",
                path.display()
            ))),
            (Entry::Directory, Expect::File) => Err(refused(format!(
                "{} is not a regular file an installation can replace",
                path.display()
            ))),
            (Entry::File(_), Expect::Folder) => Err(refused(format!(
                "{} is not a folder an installation can write into",
                path.display()
            ))),
            _ => Ok(()),
        }
    }

    /// Reads the file at `path`, or `None` where nothing is there. A directory, a link or a
    /// special file at that name is refused.
    pub(crate) fn read(&self, path: &Path) -> Result<Option<Vec<u8>>> {
        let place = self.place(path)?;
        let Some(parent) = self.parent(&place, false)? else {
            return Ok(None);
        };
        match parent.fetch(place.name, MAX_FILE_BYTES).map_err(storage)? {
            Fetched::Absent => Ok(None),
            Fetched::File(read) => Ok(Some(read.bytes)),
            Fetched::NotRegular => Err(refused(format!(
                "{} is not a regular file, and an installation reads and replaces only a regular \
                 file",
                path.display()
            ))),
            Fetched::TooLarge => Err(refused(format!(
                "{} is larger than an installation reads",
                path.display()
            ))),
        }
    }

    /// Reads the file at `path` as text, or `None` where nothing is there.
    pub(crate) fn read_text(&self, path: &Path) -> Result<Option<String>> {
        match self.read(path)? {
            None => Ok(None),
            Some(bytes) => String::from_utf8(bytes)
                .map(Some)
                .map_err(|_| refused(format!("{} is not text", path.display()))),
        }
    }

    /// The digest of the file at `path`, or `None` where nothing is there.
    pub(crate) fn digest(&self, path: &Path) -> Result<Option<Digest256>> {
        Ok(self.read(path)?.map(|bytes| digest_of(&bytes)))
    }

    /// True when a folder is at `path`, found without following a link.
    pub(crate) fn is_directory(&self, path: &Path) -> Result<bool> {
        if self.is_root(path) {
            return Ok(true);
        }
        let place = self.place(path)?;
        let Some(parent) = self.parent(&place, false)? else {
            return Ok(false);
        };
        Ok(matches!(
            parent.entry(place.name).map_err(storage)?,
            Entry::Directory
        ))
    }

    /// True when anything is at `path`.
    pub(crate) fn exists(&self, path: &Path) -> Result<bool> {
        if self.is_root(path) {
            return Ok(true);
        }
        let place = self.place(path)?;
        let Some(parent) = self.parent(&place, false)? else {
            return Ok(false);
        };
        Ok(!matches!(
            parent.entry(place.name).map_err(storage)?,
            Entry::Absent
        ))
    }

    /// The folders on the way to `path` that are not there yet, shallowest first, with `path`
    /// itself last where it is a folder that is missing.
    pub(crate) fn missing_folders(&self, folder: &Path) -> Result<Vec<PathBuf>> {
        if self.is_root(folder) {
            return Ok(Vec::new());
        }
        let place = self.place(folder)?;
        let mut missing = Vec::new();
        let mut held: Option<Dir> = None;
        let mut so_far = self.path.clone();
        let mut names = place.folders.clone();
        names.push(place.name);
        for name in names {
            so_far.push(name);
            if !missing.is_empty() {
                missing.push(so_far.clone());
                continue;
            }
            let from = held.as_ref().unwrap_or(&self.root);
            match from.child(name).map_err(storage)? {
                Child::Directory(next) => held = Some(next),
                Child::Absent => missing.push(so_far.clone()),
                Child::NotADirectory => {
                    return Err(refused(format!(
                        "{} is a link or a file, and an installation follows no link and writes \
                         nothing below a file",
                        so_far.display()
                    )));
                }
            }
        }
        Ok(missing)
    }

    /// Makes the folder at `path` and the missing ones before it, each flushed. True where this
    /// call made `folder` itself, and false where it was there, which includes a folder that
    /// another process made after this call looked and before it made it.
    pub(crate) fn make_folders(&self, folder: &Path) -> Result<bool> {
        if self.is_root(folder) {
            return Ok(false);
        }
        let place = self.place(folder)?;
        let mut names = place.folders.clone();
        names.push(place.name);
        let mut held: Option<Dir> = None;
        let mut made = false;
        for name in names {
            let from = held.as_ref().unwrap_or(&self.root);
            let mut child = from.child(name).map_err(storage)?;
            made = false;
            if matches!(child, Child::Absent) {
                #[cfg(test)]
                make_pause::run(folder);
                made = from.make_child(name).map_err(storage)?;
                from.flush().map_err(storage)?;
                child = from.child(name).map_err(storage)?;
            }
            match child {
                Child::Directory(next) => held = Some(next),
                Child::Absent | Child::NotADirectory => {
                    return Err(refused(format!(
                        "{} is not a folder an installation can write into",
                        folder.display()
                    )));
                }
            }
        }
        Ok(made)
    }

    /// Refuses the folder that holds `path`, a place below the selected root, where another user can
    /// change it. A folder that is not there yet is made by this host, and is judged at the write.
    pub(crate) fn refuse_shared_folder(&self, path: &Path) -> Result<()> {
        if self.is_root(path) {
            return Ok(());
        }
        let place = self.place(path)?;
        let Some(parent) = self.parent(&place, false)? else {
            return Ok(());
        };
        check_folder(&parent, path)
    }

    /// Writes `bytes` to the file at `path`: staged under a temporary name beside it, flushed, and
    /// published from there, the folder flushed after. A file that is there keeps its permission
    /// bits; a new one gets `default_mode`. A folder, a link or a special file at the name is
    /// refused.
    ///
    /// `replaces` is the digest of the file the caller checked at `path`, or `None` where it found
    /// nothing. Nothing is replaced that is not that file. Where nothing stood, the file is
    /// published only if the name is still free. Where a file stood, the staged file and the place
    /// trade names in one step, and the file that came out of the place must be the file that was
    /// read, by its identity and its contents. Anything else, a file another process put there
    /// after the last read, a link or a folder, is traded back and the write is refused.
    ///
    /// Who can change what is read through the handle this write holds on the folder, or through a
    /// descriptor opened on the file, and never through a name again. The folder must be one only
    /// the acting user can change, and so must a file that is to be replaced, or the write is
    /// refused before anything is staged. The staged file's owner, group, mode and access list are
    /// read through its own descriptor before any byte goes into it: a new file carries what the
    /// folder gives a file made in it, and an allow entry refuses it; a replacement goes ahead only
    /// when its copy has the owner, group, mode and list of the file it replaces. The temporary
    /// name is made only where nothing is and the staged file is removed only where it still
    /// holds the identity it was made with, so a file another process puts under that name is not
    /// taken for it. A file that is kept stays beside the place under that name, and the refusal
    /// names it, with the path the folder had when this write walked to it.
    pub(crate) fn write(
        &self,
        path: &Path,
        bytes: &[u8],
        default_mode: u32,
        replaces: Option<Digest256>,
    ) -> Result<()> {
        let place = self.place(path)?;
        let Some(parent) = self.parent(&place, true)? else {
            return Err(refused(format!(
                "{} cannot be reached without making a folder",
                path.display()
            )));
        };
        #[cfg(test)]
        walked_pause::run(path);
        check_folder(&parent, path)?;
        let (mode, checked) = match parent.fetch(place.name, MAX_FILE_BYTES).map_err(storage)? {
            Fetched::Absent if replaces.is_none() => (default_mode, None),
            Fetched::File(read) if replaces == Some(digest_of(&read.bytes)) => {
                (read.mode, Some(read.identity))
            }
            Fetched::Absent | Fetched::File(_) => return Err(changed_since_checked(path)),
            Fetched::NotRegular | Fetched::TooLarge => {
                return Err(refused(format!(
                    "{} is not a regular file an installation can replace",
                    path.display()
                )));
            }
        };
        let existing = match checked {
            Some(identity) => Some(file_to_replace(&parent, place.name, &identity, path)?),
            None => None,
        };
        let temporary = temporary_name(place.name);
        Staged {
            parent: &parent,
            temporary: &temporary,
            name: place.name,
            path,
        }
        .publish(bytes, mode, replaces.zip(checked), existing.as_ref())?;
        parent.flush().map_err(|_| not_confirmed(path))
    }

    /// Removes the file at `path`; a name that is not there is already gone.
    pub(crate) fn remove_file(&self, path: &Path) -> Result<()> {
        let place = self.place(path)?;
        let Some(parent) = self.parent(&place, false)? else {
            return Ok(());
        };
        match parent.remove_file(place.name) {
            Ok(()) => parent.flush().map_err(storage),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(storage(error)),
        }
    }

    /// Removes the empty folder at `path`. The error says why it stayed, so the caller can report
    /// a folder that is not empty and leave it.
    pub(crate) fn remove_directory(&self, path: &Path) -> std::io::Result<()> {
        let place = self
            .place(path)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let parent = self
            .parent(&place, false)
            .map_err(|error| std::io::Error::other(error.to_string()))?
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
        parent.remove_directory(place.name)?;
        parent.flush()
    }
}

/// The refusal of a write over a file that is not the one the caller checked.
fn changed_since_checked(path: &Path) -> ControllerError {
    refused(format!(
        "{} is not what it was when this installation checked it, and an installation \
         replaces only the file it checked",
        path.display()
    ))
}

/// The refusal where the file system cannot trade two names in one step.
fn no_exchange(path: &Path) -> ControllerError {
    refused(format!(
        "{} is on a file system that cannot swap two names in one step, which an installation \
         needs to replace a file safely, so nothing is written there",
        path.display()
    ))
}

/// The refusal where the file system cannot add a name only where none is.
fn no_add(path: &Path) -> ControllerError {
    refused(format!(
        "{} is on a file system that cannot add a file without the risk of replacing another one, \
         so nothing is written there",
        path.display()
    ))
}

/// The refusal where the folder that holds a place can be changed by another user, or its access
/// list cannot be read.
fn folder_shared(cause: Cause, path: &Path) -> ControllerError {
    let because = match cause {
        Cause::AnotherOwner => "belongs to another user",
        Cause::WriteBit => "lets its group or every user change what is in it",
        Cause::ListEntry => "has an allow entry for an account not known to be yours",
    };
    refused(format!(
        "{} cannot be written safely, because the folder it is in {because}, so nothing is written \
         there",
        path.display()
    ))
}

/// The refusal where a file that is to be replaced can be changed by another user.
fn file_shared(cause: Cause, path: &Path) -> ControllerError {
    let because = match cause {
        Cause::AnotherOwner => "belongs to another user",
        Cause::WriteBit => "lets its group or every user change it",
        Cause::ListEntry => "has an allow entry for an account not known to be yours",
    };
    refused(format!(
        "{} cannot be replaced safely, because it {because}, so nothing is written there",
        path.display()
    ))
}

/// The refusal where the access list of `subject`, the folder or the file of a place, cannot be
/// read.
fn unreadable(path: &Path, subject: &Path) -> ControllerError {
    refused(format!(
        "{} cannot be written safely, because the installer cannot verify the access controls of \
         {}, so nothing is written there",
        path.display(),
        subject.display()
    ))
}

/// The refusal where a new file would be given an allow entry by the folder it is made in.
fn new_file_listed(path: &Path) -> ControllerError {
    refused(format!(
        "{} cannot be written safely, because a new file in its folder would have an allow entry \
         for an account not known to be yours, so nothing is written there",
        path.display()
    ))
}

/// The refusal where the copy would not have the owner, group and access list of the file it
/// replaces.
fn copy_differs(path: &Path) -> ControllerError {
    refused(format!(
        "{} cannot be replaced safely, because a new file in its folder would not have the owner, \
         group and access list of the file it replaces, so nothing is written there",
        path.display()
    ))
}

/// The refusal where a file was published and its folder could not be made durable.
fn not_confirmed(path: &Path) -> ControllerError {
    refused(format!(
        "{} was published, but the installer could not confirm that the change reached storage",
        path.display()
    ))
}

/// The refusal where a file another process put at the place could not be put back, so it is kept
/// under the name `name` in the folder that held the place, whose path was `kept` when this write
/// walked to it.
fn kept_aside(path: &Path, name: &str, kept: &Path) -> ControllerError {
    refused(format!(
        "{} was replaced by another process while this installation wrote it, and that file \
         could not be put back, so it is kept as {name} in the folder that held {}; its last \
         known path was {}",
        path.display(),
        path.display(),
        kept.display()
    ))
}

/// Why a name that was free could not be given the staged file.
fn new_name_refusal(error: std::io::Error, path: &Path) -> ControllerError {
    match error.kind() {
        ErrorKind::AlreadyExists => changed_since_checked(path),
        ErrorKind::Unsupported => no_add(path),
        _ => storage(error),
    }
}

/// Why the staged file and the place could not trade names.
fn trade_refusal(error: std::io::Error, path: &Path) -> ControllerError {
    match error.kind() {
        ErrorKind::NotFound => changed_since_checked(path),
        ErrorKind::Unsupported => no_exchange(path),
        _ => storage(error),
    }
}

/// Refuses the folder `folder`, which holds the place `place`, where another user can change it,
/// reading it through the handle this write holds.
fn check_folder(folder: &Dir, place: &Path) -> Result<()> {
    match folder.control().map_err(storage)? {
        Control::Own => Ok(()),
        Control::Shared(cause) => Err(folder_shared(cause, place)),
        Control::Unreadable(_) => Err(unreadable(place, folder.path())),
    }
}

/// Reads the file at `name`, which the caller checked as `checked`, through a descriptor opened on
/// it, and refuses a file another user can change or one that is not the file that was checked.
fn file_to_replace(
    parent: &Dir,
    name: &str,
    checked: &Identity,
    path: &Path,
) -> Result<Protection> {
    let Some(protection) = parent.protection(name).map_err(storage)? else {
        return Err(changed_since_checked(path));
    };
    if !protection.identity.same_object(checked) {
        return Err(changed_since_checked(path));
    }
    match protection.control() {
        Control::Own => Ok(protection),
        Control::Shared(cause) => Err(file_shared(cause, path)),
        Control::Unreadable(_) => Err(unreadable(path, path)),
    }
}

/// Why the staged copy, as its own descriptor reports it before any byte is in it, may not be
/// published: where nothing stood, an allow entry or a list that cannot be read; where a file
/// stood, any difference in owner, group, mode or access list from `existing`.
fn copy_refusal(
    copy: &Protection,
    existing: Option<&Protection>,
    path: &Path,
) -> Option<ControllerError> {
    if matches!(copy.listing, Listing::Unreadable(_)) {
        return Some(unreadable(path, path));
    }
    match existing {
        None => matches!(copy.listing, Listing::Read { allows: true, .. })
            .then(|| new_file_listed(path)),
        Some(existing) => (!existing.matches(copy)).then(|| copy_differs(path)),
    }
}

/// One write: its folder, the temporary name its file is staged under beside the place, the place's
/// name and its path.
struct Staged<'a> {
    parent: &'a Dir,
    temporary: &'a str,
    name: &'a str,
    path: &'a Path,
}

impl Staged<'_> {
    /// Stages `bytes` under the temporary name and publishes the staged file at the name, over the
    /// file the caller checked (its digest and identity), or only where the name is free.
    fn publish(
        &self,
        bytes: &[u8],
        mode: u32,
        replaces: Option<(Digest256, Identity)>,
        existing: Option<&Protection>,
    ) -> Result<()> {
        let staging = match self.parent.begin_stage(self.temporary, mode) {
            Ok(staging) => staging,
            Err(unstaged) => {
                if let Some(made) = unstaged.made {
                    self.remove_staged(&made);
                }
                return Err(storage(unstaged.error));
            }
        };
        if let Some(refusal) = copy_refusal(staging.protection(), existing, self.path) {
            self.remove_staged(&staging.identity());
            return Err(refusal);
        }
        let staged = match staging.finish(bytes) {
            Ok(staged) => staged,
            Err(unstaged) => {
                if let Some(made) = unstaged.made {
                    self.remove_staged(&made);
                }
                return Err(storage(unstaged.error));
            }
        };
        #[cfg(test)]
        publish_pause::run(self.path);
        match replaces {
            None => self
                .parent
                .rename_new(self.temporary, self.parent, self.name)
                .map_err(|error| {
                    self.remove_staged(&staged);
                    new_name_refusal(error, self.path)
                }),
            Some((expected, checked)) => self.replace_checked(&staged, &checked, expected),
        }
    }

    /// Removes what stands under the temporary name where it is the file this write made, told by
    /// its identity from the status of the name alone.
    fn remove_staged(&self, staged: &Identity) {
        let ours = matches!(
            self.parent.look(self.temporary),
            Ok(Entry::File(found)) if found.same_object(staged)
        );
        if ours {
            let _ = self.parent.remove_file(self.temporary);
        }
    }

    /// Replaces the file at the name with the staged file when the file at the name is `checked`
    /// and holds the `expected` contents. The two names trade places in one step, so the place is
    /// never absent and no check stands between a read and the replacement; the file that came out
    /// of the place is then read under the temporary name, and anything but the checked file is put
    /// back.
    fn replace_checked(
        &self,
        staged: &Identity,
        checked: &Identity,
        expected: Digest256,
    ) -> Result<()> {
        if let Err(error) = self.parent.exchange(self.temporary, self.parent, self.name) {
            // The names did not trade, so the staged file is still under its temporary name.
            self.remove_staged(staged);
            return Err(trade_refusal(error, self.path));
        }
        #[cfg(test)]
        trade_pause::run(self.path);
        match self.parent.fetch(self.temporary, MAX_FILE_BYTES) {
            Ok(Fetched::File(read))
                if read.identity.same_object(checked) && digest_of(&read.bytes) == expected =>
            {
                #[cfg(test)]
                cleanup_pause::run(self.path);
                self.parent.remove_file(self.temporary).map_err(storage)
            }
            _ => Err(self.put_back(staged)),
        }
    }

    /// Undoes a trade that took a file other than the checked one out of the place. The staged file
    /// is removed only where it is the one this write made; a file that is not, and the file taken
    /// out of the place where it cannot go back, stay under the temporary name.
    fn put_back(&self, staged: &Identity) -> ControllerError {
        let back = match self.parent.exchange(self.temporary, self.parent, self.name) {
            Ok(()) => true,
            // Something took the staged file from the place: the file taken out of it goes back to
            // the free name.
            Err(error) if error.kind() == ErrorKind::NotFound => self
                .parent
                .rename_new(self.temporary, self.parent, self.name)
                .is_ok(),
            Err(_) => false,
        };
        match self.parent.look(self.temporary) {
            Ok(Entry::Absent) if back => changed_since_checked(self.path),
            Ok(Entry::File(found)) if back && found.same_object(staged) => {
                #[cfg(test)]
                cleanup_pause::run(self.path);
                let _ = self.parent.remove_file(self.temporary);
                changed_since_checked(self.path)
            }
            _ => kept_aside(self.path, self.temporary, &self.parent.join(self.temporary)),
        }
    }
}

/// What the unit tests run in a write after its file is staged and before it is published, to make
/// the change another process could make between the two.
#[cfg(test)]
pub(crate) mod publish_pause {
    use std::cell::RefCell;
    use std::path::Path;

    type Then = Box<dyn FnOnce(&Path)>;

    thread_local! {
        static BEFORE_PUBLISH: RefCell<Option<Then>> = const { RefCell::new(None) };
    }

    /// Runs `then` once, the next time a write on this thread has staged its file.
    #[cfg(unix)]
    pub(crate) fn once(then: impl FnOnce(&Path) + 'static) {
        BEFORE_PUBLISH.with(|before| *before.borrow_mut() = Some(Box::new(then)));
    }

    pub(crate) fn run(path: &Path) {
        if let Some(then) = BEFORE_PUBLISH.with(|before| before.borrow_mut().take()) {
            then(path);
        }
    }
}

/// What the unit tests run in a write after the staged file and the place have traded names and
/// before the file that came out of the place is read, to make the change another process could
/// make in between.
#[cfg(test)]
pub(crate) mod trade_pause {
    use std::cell::RefCell;
    use std::path::Path;

    type Then = Box<dyn FnOnce(&Path)>;

    thread_local! {
        static AFTER_TRADE: RefCell<Option<Then>> = const { RefCell::new(None) };
    }

    /// Runs `then` once, the next time a write on this thread has traded the names.
    #[cfg(unix)]
    pub(crate) fn once(then: impl FnOnce(&Path) + 'static) {
        AFTER_TRADE.with(|after| *after.borrow_mut() = Some(Box::new(then)));
    }

    pub(crate) fn run(path: &Path) {
        if let Some(then) = AFTER_TRADE.with(|after| after.borrow_mut().take()) {
            then(path);
        }
    }
}

/// What the unit tests run in a write after it has read a staged or displaced file and before it
/// removes that file, to make the change another process could make between the two.
#[cfg(test)]
pub(crate) mod cleanup_pause {
    use std::cell::RefCell;
    use std::path::Path;

    type Then = Box<dyn FnOnce(&Path)>;

    thread_local! {
        static BEFORE_REMOVAL: RefCell<Option<Then>> = const { RefCell::new(None) };
    }

    pub(crate) fn run(path: &Path) {
        if let Some(then) = BEFORE_REMOVAL.with(|before| before.borrow_mut().take()) {
            then(path);
        }
    }
}

/// What the unit tests run in a write right after its walk to the place's folder, to make the change
/// another process could make to that folder's name in between. The hook is given the place's path.
#[cfg(test)]
pub(crate) mod walked_pause {
    use std::cell::RefCell;
    use std::path::Path;

    type Then = Box<dyn FnOnce(&Path)>;

    thread_local! {
        static AFTER_WALK: RefCell<Option<Then>> = const { RefCell::new(None) };
    }

    /// Runs `then` once, the next time a write on this thread has walked to its folder.
    #[cfg(unix)]
    pub(crate) fn once(then: impl FnOnce(&Path) + 'static) {
        AFTER_WALK.with(|after| *after.borrow_mut() = Some(Box::new(then)));
    }

    pub(crate) fn run(path: &Path) {
        if let Some(then) = AFTER_WALK.with(|after| after.borrow_mut().take()) {
            then(path);
        }
    }
}

/// Lets a test make the folder another process would make between a look and the making.
#[cfg(test)]
pub(crate) mod make_pause {
    use std::cell::RefCell;
    use std::path::Path;

    type Then = Box<dyn FnOnce(&Path)>;

    thread_local! {
        static BEFORE_MAKE: RefCell<Option<Then>> = const { RefCell::new(None) };
    }

    /// Runs `then` once, the next time a folder on this thread is about to be made.
    #[cfg(unix)]
    pub(crate) fn once(then: impl FnOnce(&Path) + 'static) {
        BEFORE_MAKE.with(|before| *before.borrow_mut() = Some(Box::new(then)));
    }

    pub(crate) fn run(path: &Path) {
        if let Some(then) = BEFORE_MAKE.with(|before| before.borrow_mut().take()) {
            then(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Error;

    use super::*;

    fn detail(refusal: ControllerError) -> String {
        match refusal {
            ControllerError::PermissionDenied { detail } => detail,
            other => panic!("not a refusal: {other}"),
        }
    }

    /// A file system that cannot add a file only where none is, or cannot trade two names, is
    /// refused in the words a person is shown; a name that is taken, or a file that is gone, is the
    /// refusal of a file that changed.
    #[test]
    fn a_file_system_without_the_two_renames_is_refused_in_the_words_a_person_is_shown() {
        let path = Path::new("/home/p/.amp/mcp.json");
        assert_eq!(
            detail(new_name_refusal(Error::from(ErrorKind::Unsupported), path)),
            "/home/p/.amp/mcp.json is on a file system that cannot add a file without the risk of \
             replacing another one, so nothing is written there"
        );
        assert_eq!(
            detail(trade_refusal(Error::from(ErrorKind::Unsupported), path)),
            "/home/p/.amp/mcp.json is on a file system that cannot swap two names in one step, \
             which an installation needs to replace a file safely, so nothing is written there"
        );
        for refusal in [
            new_name_refusal(Error::from(ErrorKind::AlreadyExists), path),
            trade_refusal(Error::from(ErrorKind::NotFound), path),
        ] {
            assert!(
                detail(refusal).contains("replaces only the file it checked"),
                "a name that is taken or a file that is gone is a changed file"
            );
        }
    }

    /// The refusals of a folder, a file and a copy are made in the words a person is shown.
    #[test]
    fn a_folder_a_file_and_a_copy_are_refused_in_the_words_a_person_is_shown() {
        let path = Path::new("/home/p/.amp/mcp.json");
        assert_eq!(
            detail(folder_shared(Cause::AnotherOwner, path)),
            "/home/p/.amp/mcp.json cannot be written safely, because the folder it is in belongs \
             to another user, so nothing is written there"
        );
        assert_eq!(
            detail(folder_shared(Cause::WriteBit, path)),
            "/home/p/.amp/mcp.json cannot be written safely, because the folder it is in lets its \
             group or every user change what is in it, so nothing is written there"
        );
        assert_eq!(
            detail(folder_shared(Cause::ListEntry, path)),
            "/home/p/.amp/mcp.json cannot be written safely, because the folder it is in has an \
             allow entry for an account not known to be yours, so nothing is written there"
        );
        assert_eq!(
            detail(unreadable(path, Path::new("/home/p/.amp"))),
            "/home/p/.amp/mcp.json cannot be written safely, because the installer cannot verify \
             the access controls of /home/p/.amp, so nothing is written there"
        );
        assert_eq!(
            detail(new_file_listed(path)),
            "/home/p/.amp/mcp.json cannot be written safely, because a new file in its folder \
             would have an allow entry for an account not known to be yours, so nothing is written \
             there"
        );
        assert_eq!(
            detail(file_shared(Cause::AnotherOwner, path)),
            "/home/p/.amp/mcp.json cannot be replaced safely, because it belongs to another user, \
             so nothing is written there"
        );
        assert_eq!(
            detail(file_shared(Cause::WriteBit, path)),
            "/home/p/.amp/mcp.json cannot be replaced safely, because it lets its group or every \
             user change it, so nothing is written there"
        );
        assert_eq!(
            detail(file_shared(Cause::ListEntry, path)),
            "/home/p/.amp/mcp.json cannot be replaced safely, because it has an allow entry for an \
             account not known to be yours, so nothing is written there"
        );
        assert_eq!(
            detail(copy_differs(path)),
            "/home/p/.amp/mcp.json cannot be replaced safely, because a new file in its folder \
             would not have the owner, group and access list of the file it replaces, so nothing \
             is written there"
        );
    }

    /// A copy is refused where it was given an allow entry or a list that cannot be read, and, over a
    /// file, where its owner, group, mode or list is not that file's.
    #[test]
    fn a_copy_is_refused_for_a_list_it_cannot_read_an_allow_entry_or_any_difference() {
        use crate::catalogue::native_bridge::tree::Owners;

        let path = Path::new("/home/p/.amp/mcp.json");
        let protection = |user, group, mode, entries: &[&str], allows| Protection {
            identity: Identity {
                device: 1,
                inode: 2,
                size: 0,
                modified_seconds: 0,
                modified_nanoseconds: 0,
            },
            owners: Owners { user, group },
            mode,
            listing: Listing::Read {
                entries: entries.iter().map(|entry| (*entry).to_owned()).collect(),
                allows,
            },
        };
        let said = |refusal: Option<ControllerError>| detail(refusal.expect("refused"));
        let plain = protection(501, 20, 0o600, &[], false);
        assert!(
            copy_refusal(&plain, None, path).is_none(),
            "a plain new file"
        );
        assert!(
            copy_refusal(&protection(501, 20, 0o600, &["deny"], false), None, path).is_none(),
            "a new file carries an entry that denies"
        );
        assert_eq!(
            said(copy_refusal(
                &protection(501, 20, 0o600, &["allow"], true),
                None,
                path
            )),
            detail(new_file_listed(path)),
            "a new file with an allow entry"
        );
        let unreadable_copy = Protection {
            listing: Listing::Unreadable("no".to_owned()),
            ..plain.clone()
        };
        for existing in [None, Some(&plain)] {
            assert_eq!(
                said(copy_refusal(&unreadable_copy, existing, path)),
                detail(unreadable(path, path)),
                "a list that cannot be read"
            );
        }
        assert!(
            copy_refusal(&plain, Some(&plain), path).is_none(),
            "an equal copy"
        );
        for (what, other) in [
            ("another owner", protection(502, 20, 0o600, &[], false)),
            ("another group", protection(501, 21, 0o600, &[], false)),
            ("another mode", protection(501, 20, 0o640, &[], false)),
            ("another list", protection(501, 20, 0o600, &["deny"], false)),
        ] {
            assert_eq!(
                said(copy_refusal(&plain, Some(&other), path)),
                detail(copy_differs(path)),
                "{what}"
            );
        }
    }

    /// A file published whose folder could not be made durable, and a file kept beside the place,
    /// are told in the words a person is shown.
    #[test]
    fn a_published_file_not_confirmed_and_a_kept_file_are_told_in_the_words_a_person_is_shown() {
        let path = Path::new("/home/p/.amp/mcp.json");
        assert_eq!(
            detail(not_confirmed(path)),
            "/home/p/.amp/mcp.json was published, but the installer could not confirm that the \
             change reached storage"
        );
        assert_eq!(
            detail(kept_aside(
                path,
                ".mcp.json.0a1b2c.kalareach",
                Path::new("/home/p/.amp/.mcp.json.0a1b2c.kalareach")
            )),
            "/home/p/.amp/mcp.json was replaced by another process while this installation wrote \
             it, and that file could not be put back, so it is kept as .mcp.json.0a1b2c.kalareach \
             in the folder that held /home/p/.amp/mcp.json; its last known path was \
             /home/p/.amp/.mcp.json.0a1b2c.kalareach"
        );
    }
}
