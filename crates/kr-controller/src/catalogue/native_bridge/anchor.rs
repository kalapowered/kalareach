//! The folder an installation for a declared agent is written under, walked from one handle on it.
//! It lives beside the native bridge's walk, whose handle type it uses.
//!
//! A package declares the places, so the host cannot know them to be its own. Every name an
//! installation for a declared word reads, writes or removes is reached from the handle this host
//! opened once on the selected root (the home folder, or the project folder the request names),
//! one component at a time, each opened without following a link. A link or a file at any
//! component stops the walk by name before anything below it is touched, so a place a person
//! replaced with a link between the check and the write is refused rather than followed. A file is
//! published under a temporary name beside its destination and renamed into place; the folder is
//! flushed after.

use std::path::{Component, Path, PathBuf};

use kr_protocol::scalars::Digest256;

use super::tree::{Child, Dir, Entry, Fetched};
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
            Ok(handle) => Ok(Some(Self {
                root: handle,
                path: root.to_path_buf(),
            })),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(storage(error)),
        }
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
            None => Ok(Some(self.reopened()?)),
        }
    }

    fn reopened(&self) -> Result<Dir> {
        Dir::open(&self.path).map_err(storage)
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

    /// Makes the folder at `path` and the missing ones before it, each flushed.
    pub(crate) fn make_folders(&self, folder: &Path) -> Result<()> {
        if self.is_root(folder) {
            return Ok(());
        }
        let place = self.place(folder)?;
        let mut names = place.folders.clone();
        names.push(place.name);
        let mut held: Option<Dir> = None;
        for name in names {
            let from = held.as_ref().unwrap_or(&self.root);
            let mut child = from.child(name).map_err(storage)?;
            if matches!(child, Child::Absent) {
                from.make_child(name).map_err(storage)?;
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
        Ok(())
    }

    /// Writes `bytes` to the file at `path`: under a temporary name beside it, flushed, and renamed
    /// into place, the folder flushed after. A file that is there keeps its permission bits; a new
    /// one gets `default_mode`. A folder, a link or a special file at the name is refused.
    pub(crate) fn write(&self, path: &Path, bytes: &[u8], default_mode: u32) -> Result<()> {
        let place = self.place(path)?;
        let Some(parent) = self.parent(&place, true)? else {
            return Err(refused(format!(
                "{} cannot be reached without making a folder",
                path.display()
            )));
        };
        let mode = match parent.fetch(place.name, MAX_FILE_BYTES).map_err(storage)? {
            Fetched::Absent => default_mode,
            Fetched::File(read) => read.mode,
            Fetched::NotRegular | Fetched::TooLarge => {
                return Err(refused(format!(
                    "{} is not a regular file an installation can replace",
                    path.display()
                )));
            }
        };
        let temporary = format!(
            ".{}.{}.kalareach",
            place.name,
            crate::catalogue::files::hex(&kr_cbor::sha256(kr_ipc::new_uuid().as_bytes())[..6])
        );
        if let Err(unstaged) = parent.stage(&temporary, bytes, mode) {
            if unstaged.made.is_some() {
                let _ = parent.remove_file(&temporary);
            }
            return Err(storage(unstaged.error));
        }
        if let Err(error) = parent.rename_over(&temporary, place.name) {
            let _ = parent.remove_file(&temporary);
            return Err(storage(error));
        }
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
