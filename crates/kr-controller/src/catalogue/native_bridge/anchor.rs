//! The folder an installation for a declared agent is written under, walked from one handle on it.
//! It lives beside the native bridge's walk, whose handle type it uses.
//!
//! A package declares the places, so the host cannot know them to be its own. Every name an
//! installation for a declared word reads, writes or removes is reached from the handle this host
//! opened once on the selected root (the home folder, or the project folder the request names),
//! one component at a time, each opened without following a link. A link or a file at any
//! component stops the walk by name before anything below it is touched, so a place a person
//! replaced with a link between the check and the write is refused rather than followed. A file is
//! staged in a private folder beside its destination and published from there; the folder is
//! flushed after.

use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};

use kr_protocol::scalars::Digest256;

use super::tree::{Child, Dir, Entry, Fetched, Identity, Made, temporary_name};
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

    /// Writes `bytes` to the file at `path`: staged in a private folder beside it, flushed, and
    /// published from there, the folder flushed after. A file that is there keeps its permission
    /// bits; a new one gets `default_mode`. A folder, a link or a special file at the name is
    /// refused.
    ///
    /// `replaces` is the digest of the file the caller checked at `path`, or `None` where it found
    /// nothing. Nothing is replaced that is not that file. Where nothing stood, the file is
    /// published only if the name is still free. Where a file stood, the staged file and the place
    /// trade names in one step, and the file that came out of the place is read: it must hold the
    /// checked contents. Anything else, a file another process put there after the last read, a
    /// link or a folder, is traded back and the write is refused.
    ///
    /// The private folder is made by this write and opened once. What was opened is read through
    /// its handle: it must be this user's, give the group and others no permission bit, carry no
    /// access-list entry of its own on macOS and hold nothing, or the write is refused before
    /// anything is staged. A folder that fails the owner, mode or contents check stays where it is,
    /// since nothing proves this write made it. Every step on the staged file goes through the
    /// handle this write holds on that folder, never through a name in the shared folder, so the
    /// staged file and the file a trade displaces are removed from there and a file another process
    /// puts under the folder's own name is never removed. The folder is removed by its name when the
    /// write ends. The kernel refuses to remove a folder that holds anything, so a file kept in it
    /// stays. Between the two trades the place holds the new contents and the displaced file is in
    /// the folder; it is removed only where it is the checked file. Where it cannot be put back it
    /// is kept there, and the refusal names where.
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
        let mode = match parent.fetch(place.name, MAX_FILE_BYTES).map_err(storage)? {
            Fetched::Absent if replaces.is_none() => default_mode,
            Fetched::File(read) if replaces == Some(digest_of(&read.bytes)) => read.mode,
            Fetched::Absent | Fetched::File(_) => return Err(changed_since_checked(path)),
            Fetched::NotRegular | Fetched::TooLarge => {
                return Err(refused(format!(
                    "{} is not a regular file an installation can replace",
                    path.display()
                )));
            }
        };
        let folder = temporary_name(place.name);
        let staging = match parent.make_private(&folder).map_err(storage)? {
            Made::Private(staging) => staging,
            Made::OpenToOthers => return Err(open_to_others(path)),
            Made::Occupied => return Err(occupied(path)),
        };
        let published = publish(&parent, &staging, place.name, path, bytes, mode, replaces);
        // Removed by its name: a folder that holds anything stays, and so does a file another
        // process put under that name.
        let _ = parent.remove_directory(&folder);
        published?;
        parent.flush().map_err(storage)
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

/// The refusal where the temporary folder a write needs beside its place can be entered by another
/// user.
fn open_to_others(path: &Path) -> ControllerError {
    refused(format!(
        "{} cannot be written safely, because the temporary folder beside it is open to other \
         users, so nothing is written there",
        path.display()
    ))
}

/// The refusal where the temporary folder a write needs beside its place already holds something.
fn occupied(path: &Path) -> ControllerError {
    refused(format!(
        "{} cannot be written safely, because another program put something in the temporary \
         folder beside it, so nothing is written there",
        path.display()
    ))
}

/// The refusal where a file another process put at the place could not be put back, so it is kept
/// under the name `kept`.
fn kept_aside(path: &Path, kept: &Path) -> ControllerError {
    refused(format!(
        "{} was replaced by another process while this installation wrote it, and that file \
         could not be put back, so it is kept as {}",
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

/// The name of the staged file in its private folder.
const STAGED: &str = "staged";

/// Stages `bytes` in `staging` and publishes the staged file at `name` in `parent`, over the file
/// the caller checked, or only where the name is free.
fn publish(
    parent: &Dir,
    staging: &Dir,
    name: &str,
    path: &Path,
    bytes: &[u8],
    mode: u32,
    replaces: Option<Digest256>,
) -> Result<()> {
    let staged = match staging.stage(STAGED, bytes, mode) {
        Ok(staged) => staged,
        Err(unstaged) => {
            if let Some(made) = unstaged.made {
                remove_staged(staging, &made);
            }
            return Err(storage(unstaged.error));
        }
    };
    #[cfg(test)]
    publish_pause::run(path);
    match replaces {
        None => staging.rename_new(STAGED, parent, name).map_err(|error| {
            remove_staged(staging, &staged);
            new_name_refusal(error, path)
        }),
        Some(expected) => replace_checked(parent, staging, name, &staged, expected, path),
    }
}

/// Removes the staged file from its private folder where it is the file this write made.
fn remove_staged(staging: &Dir, staged: &Identity) {
    let ours = matches!(
        staging.fetch(STAGED, MAX_FILE_BYTES),
        Ok(Fetched::File(read)) if read.identity.same_object(staged)
    );
    if ours {
        let _ = staging.remove_file(STAGED);
    }
}

/// Replaces the file at `name` with the staged file when the file at `name` holds the `expected`
/// contents. The two names trade places in one step, so the place is never absent and no check
/// stands between a read and the replacement; the file that came out of the place is then read in
/// the private folder, and anything but the expected file is put back.
fn replace_checked(
    parent: &Dir,
    staging: &Dir,
    name: &str,
    staged: &Identity,
    expected: Digest256,
    path: &Path,
) -> Result<()> {
    if let Err(error) = staging.exchange(STAGED, parent, name) {
        // The names did not trade, so the staged file is still in its folder.
        remove_staged(staging, staged);
        return Err(trade_refusal(error, path));
    }
    #[cfg(test)]
    trade_pause::run(path);
    match staging.fetch(STAGED, MAX_FILE_BYTES) {
        Ok(Fetched::File(read)) if digest_of(&read.bytes) == expected => {
            #[cfg(test)]
            cleanup_pause::run(path);
            staging.remove_file(STAGED).map_err(storage)
        }
        _ => Err(put_back(parent, staging, name, staged, path)),
    }
}

/// Undoes a trade that took a file other than the checked one out of the place. The staged file is
/// removed only where it is the one this write made; a file that is not, and the file taken out of
/// the place where it cannot go back, are kept in the private folder.
fn put_back(
    parent: &Dir,
    staging: &Dir,
    name: &str,
    staged: &Identity,
    path: &Path,
) -> ControllerError {
    let back = match staging.exchange(STAGED, parent, name) {
        Ok(()) => true,
        // Something took the staged file from the place: the file taken out of it goes back to
        // the free name.
        Err(error) if error.kind() == ErrorKind::NotFound => {
            staging.rename_new(STAGED, parent, name).is_ok()
        }
        Err(_) => false,
    };
    match staging.fetch(STAGED, MAX_FILE_BYTES) {
        Ok(Fetched::Absent) if back => changed_since_checked(path),
        Ok(Fetched::File(read)) if back && read.identity.same_object(staged) => {
            #[cfg(test)]
            cleanup_pause::run(path);
            let _ = staging.remove_file(STAGED);
            changed_since_checked(path)
        }
        _ => kept_aside(path, &staging.join(STAGED)),
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

    /// Runs `then` once, the next time a write on this thread is about to remove a file it staged
    /// or displaced.
    #[cfg(unix)]
    pub(crate) fn once(then: impl FnOnce(&Path) + 'static) {
        BEFORE_REMOVAL.with(|before| *before.borrow_mut() = Some(Box::new(then)));
    }

    pub(crate) fn run(path: &Path) {
        if let Some(then) = BEFORE_REMOVAL.with(|before| before.borrow_mut().take()) {
            then(path);
        }
    }
}

/// What the unit tests run in a write after its private folder is made and before it is opened, to
/// make the change another process could make between the two. The hook is given the folder's
/// path.
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
pub(crate) mod private_pause {
    use std::cell::RefCell;
    use std::path::Path;

    type Then = Box<dyn FnOnce(&Path)>;

    thread_local! {
        static BEFORE_OPEN: RefCell<Option<Then>> = const { RefCell::new(None) };
    }

    /// Runs `then` once, the next time a private folder on this thread is about to be opened.
    pub(crate) fn once(then: impl FnOnce(&Path) + 'static) {
        BEFORE_OPEN.with(|before| *before.borrow_mut() = Some(Box::new(then)));
    }

    pub(crate) fn run(path: &Path) {
        if let Some(then) = BEFORE_OPEN.with(|before| before.borrow_mut().take()) {
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

    /// A temporary folder that another user can enter is refused in the words a person is shown.
    #[test]
    fn a_temporary_folder_other_users_can_enter_is_refused_in_the_words_a_person_is_shown() {
        assert_eq!(
            detail(open_to_others(Path::new("/home/p/.amp/mcp.json"))),
            "/home/p/.amp/mcp.json cannot be written safely, because the temporary folder beside \
             it is open to other users, so nothing is written there"
        );
    }

    /// A temporary folder that already holds something is refused in the words a person is shown.
    #[test]
    fn a_temporary_folder_that_holds_something_is_refused_in_the_words_a_person_is_shown() {
        assert_eq!(
            detail(occupied(Path::new("/home/p/.amp/mcp.json"))),
            "/home/p/.amp/mcp.json cannot be written safely, because another program put \
             something in the temporary folder beside it, so nothing is written there"
        );
    }
}
